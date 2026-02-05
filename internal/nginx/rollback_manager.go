package nginx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	license_reporting "github.com/nginx/kubernetes-ingress/internal/license_reporting"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/metadata"
	"github.com/nginx/kubernetes-ingress/internal/metrics/collectors"
)

// ConfigRollbackManager wraps LocalManager and adds rollback protection for main and regular configs.
type ConfigRollbackManager struct {
	*LocalManager
}

// NewConfigRollbackManager creates a ConfigRollbackManager.
func NewConfigRollbackManager(ctx context.Context, confPath string, debug bool, mc collectors.ManagerCollector, lr *license_reporting.LicenseReporter, metadata *metadata.Metadata, timeout time.Duration, nginxPlus bool) *ConfigRollbackManager {
	lm := NewLocalManager(ctx, confPath, debug, mc, lr, metadata, timeout, nginxPlus)
	return &ConfigRollbackManager{LocalManager: lm}
}

// CreateMainConfig creates the main NGINX configuration file after validating it won't break nginx.
// If validation fails, attempts rollback to previous working config.
// Skips testing on first iteration (configVersion == 0) when dependencies may not exist yet.
func (cm *ConfigRollbackManager) CreateMainConfig(content []byte) (bool, error) {
	// Skip testing on first iteration when configVersion is 0
	// During startup, dependencies like tls-passthrough-hosts.conf may not exist yet
	if cm.configVersion == 0 {
		nl.Debugf(cm.logger, "Skipping validation on first iteration (configVersion == 0)")
		return cm.LocalManager.CreateMainConfig(content)
	}

	existingConfigPath := cm.mainConfFilename
	// #nosec G304 -- existingConfigPath is constructed from safe internal path
	if existingContent, err := os.ReadFile(existingConfigPath); err == nil {
		// If the existing config is identical to what we're trying to write,
		// we need to check if the current overall nginx config is valid
		if bytes.Equal(existingContent, content) {
			if testErr := cm.TestConfig(); testErr == nil {
				nl.Debugf(cm.logger, "Main configuration is already applied and working")
				return false, nil
			} else {
				nl.Warnf(cm.logger, "Main configuration was already validated and found invalid")
				return false, fmt.Errorf("%w: %v", ErrMainConfigValidation, testErr)
			}
		}
	}

	// Store backup of existing working config before making changes
	var previousConfig []byte
	var hadPreviousConfig bool
	// #nosec G304 -- existingConfigPath is constructed from safe internal path
	if existingContent, err := os.ReadFile(existingConfigPath); err == nil {
		if testErr := cm.TestConfig(); testErr == nil {
			previousConfig = existingContent
			hadPreviousConfig = true
			nl.Debugf(cm.logger, "Backing up current working main config")
		}
	}

	changed, _ := cm.LocalManager.CreateMainConfig(content)

	if err := cm.TestConfig(); err != nil {
		nl.Debugf(cm.logger, "Nginx main configuration validation failed: %v", err)
		if hadPreviousConfig {
			nl.Infof(cm.logger, "Rolling back main config to previous working configuration")
			if rollbackErr := createFileAndWrite(existingConfigPath, previousConfig); rollbackErr != nil {
				nl.Errorf(cm.logger, "Failed to rollback main config to previous config: %v", rollbackErr)
				return false, fmt.Errorf("%w: %v", ErrMainConfigValidation, err)
			}

			if testErr := cm.TestConfig(); testErr == nil {
				nl.Infof(cm.logger, "Successfully rolled back main config to previous working configuration")
				if reloadErr := cm.Reload(false); reloadErr != nil {
					nl.Warnf(cm.logger, "Failed to reload after rollback: %v", reloadErr)
				} else {
					nl.Infof(cm.logger, "Successfully reloaded nginx after rollback, workers restarted")
				}
				return false, fmt.Errorf("%w: %v", ErrMainConfigValidation, err)
			}
			testErr := cm.TestConfig()
			nl.Warnf(cm.logger, "Rollback of main config didn't resolve validation issues: %v", testErr)
			return false, fmt.Errorf("%w: %v", ErrMainConfigValidation, err)
		}

		nl.Warnf(cm.logger, "No previous main config to rollback to, keeping invalid config for debugging")
		return false, fmt.Errorf("%w: %v", ErrMainConfigValidation, err)
	}

	return changed, nil
}

// CreateConfig creates a configuration file after validating it won't break nginx.
// If validation fails, attempts rollback to previous working config.
func (cm *ConfigRollbackManager) CreateConfig(name string, content []byte) (bool, error) {
	existingConfigPath := cm.getFilenameForConfig(name)
	// #nosec G304 -- existingConfigPath is constructed from safe internal path
	if existingContent, err := os.ReadFile(existingConfigPath); err == nil {
		if bytes.Equal(existingContent, content) {
			if testErr := cm.TestConfig(); testErr == nil {
				nl.Debugf(cm.logger, "Configuration %s is already applied and working", name)
				return false, nil
			}
			return false, fmt.Errorf("configuration %s was already validated and found invalid", name)
		}
	}

	var previousConfig []byte
	var hadPreviousConfig bool
	// #nosec G304 -- existingConfigPath is constructed from safe internal path
	if existingContent, err := os.ReadFile(existingConfigPath); err == nil {
		if testErr := cm.TestConfig(); testErr == nil {
			previousConfig = existingContent
			hadPreviousConfig = true
			nl.Debugf(cm.logger, "Backing up current working config for %s", name)
		}
	}

	changed, _ := cm.LocalManager.CreateConfig(name, content)

	if err := cm.TestConfig(); err != nil {
		nl.Debugf(cm.logger, "Nginx configuration validation failed for %s: %v", name, err)
		if hadPreviousConfig {
			nl.Infof(cm.logger, "Rolling back %s to previous working configuration", name)
			if rollbackErr := createFileAndWrite(existingConfigPath, previousConfig); rollbackErr != nil {
				nl.Errorf(cm.logger, "Failed to rollback %s to previous config: %v", name, rollbackErr)
				cm.DeleteConfig(name)
				return false, fmt.Errorf("configuration validation failed and rollback failed for %s: %w", name, err)
			}

			if testErr := cm.TestConfig(); testErr == nil {
				nl.Infof(cm.logger, "Successfully rolled back %s to previous working configuration", name)
				if reloadErr := cm.Reload(false); reloadErr != nil {
					nl.Warnf(cm.logger, "Failed to reload after rollback: %v", reloadErr)
				} else {
					nl.Infof(cm.logger, "Successfully reloaded nginx after rollback, workers restarted")
				}
				return false, fmt.Errorf("configuration validation failed for %s, rolled back to previous working config", name)
			}
			testErr := cm.TestConfig()
			nl.Warnf(cm.logger, "Rollback of %s didn't resolve validation issues: %v", name, testErr)
			cm.DeleteConfig(name)
			return false, fmt.Errorf("configuration validation failed and rollback didn't resolve issues for %s: %w", name, err)
		}

		nl.Warnf(cm.logger, "No previous config to rollback to for %s, deleting invalid config", name)
		cm.DeleteConfig(name)
		return false, fmt.Errorf("configuration validation failed for %s: %w", name, err)
	}

	return changed, nil
}
