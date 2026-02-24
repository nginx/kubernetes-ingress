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

// testConfig tests the nginx configuration for syntax errors and file accessibility.
func (cm *ConfigRollbackManager) testConfig() error {
	nl.Debugf(cm.logger, "Testing nginx configuration")

	binaryFilename := getBinaryFileName(cm.debug)
	testCmd := fmt.Sprintf("%v -t -q", binaryFilename)

	if err := shellOut(cm.logger, testCmd); err != nil {
		return fmt.Errorf("nginx configuration test failed: %w", err)
	}

	nl.Debugf(cm.logger, "Nginx configuration test passed")
	return nil
}

// createConfigWithRollback replaces the simple createFileAndWrite in the LocalManager flow with a
// rollback-protected write: read existing → backup → write → validate → rollback.
// If isMainConfig is false, the config file is deleted on unrecoverable failure.
func (cm *ConfigRollbackManager) createConfigWithRollback(name string, configPath string, content []byte, isMainConfig bool) (bool, error) {
	var backup []byte
	hasBackup := false

	// #nosec G304 -- configPath is constructed from safe internal paths
	if existingContent, readErr := os.ReadFile(configPath); readErr == nil {
		if bytes.Equal(existingContent, content) {
			if testErr := cm.testConfig(); testErr == nil {
				nl.Debugf(cm.logger, "Configuration %s is already applied and working", name)
				return false, nil
			}
			nl.Warnf(cm.logger, "Configuration %s was already validated and found invalid", name)
			return false, fmt.Errorf("configuration %s was already validated and found invalid", name)
		}

		if testErr := cm.testConfig(); testErr == nil {
			nl.Debugf(cm.logger, "Backing up current working config for %s", name)
			backup = existingContent
			hasBackup = true
		}
	}

	nl.Debugf(cm.logger, "Writing config to %v", configPath)
	if err := createFileAndWrite(configPath, content); err != nil {
		nl.Fatalf(cm.logger, "Failed to write config to %v: %v", configPath, err)
	}

	if err := cm.testConfig(); err != nil {
		nl.Debugf(cm.logger, "Nginx configuration validation failed for %s: %v", name, err)
		if hasBackup {
			nl.Infof(cm.logger, "Rolling back %s to previous working configuration", name)
			if rollbackErr := createFileAndWrite(configPath, backup); rollbackErr != nil {
				nl.Errorf(cm.logger, "Failed to rollback %s to previous config: %v", name, rollbackErr)
				if !isMainConfig {
					deleteConfig(cm.logger, configPath)
				}
				return false, fmt.Errorf("configuration validation failed and rollback failed for %s: %w", name, err)
			}

			if testErr := cm.testConfig(); testErr == nil {
				nl.Infof(cm.logger, "Successfully rolled back %s to previous working configuration", name)
				if reloadErr := cm.Reload(false); reloadErr != nil {
					nl.Warnf(cm.logger, "Failed to reload after rollback: %v", reloadErr)
				} else {
					nl.Infof(cm.logger, "Successfully reloaded nginx after rollback, workers restarted")
				}
				return false, fmt.Errorf("configuration validation failed for %s, rolled back to previous working config", name)
			}
			testErr := cm.testConfig()
			nl.Warnf(cm.logger, "Rollback of %s didn't resolve validation issues: %v", name, testErr)
			if !isMainConfig {
				deleteConfig(cm.logger, configPath)
			}
			return false, fmt.Errorf("configuration validation failed and rollback didn't resolve issues for %s: %w", name, err)
		}

		nl.Warnf(cm.logger, "No previous config to rollback to for %s", name)
		if !isMainConfig {
			deleteConfig(cm.logger, configPath)
		}
		return false, fmt.Errorf("configuration validation failed for %s: %w", name, err)
	}

	return true, nil
}

// CreateMainConfig creates the main NGINX configuration file after validating it won't break nginx.
// If validation fails, attempts rollback to previous working config.
// Skips testing on first iteration (configVersion == 0) when dependencies may not exist yet.
func (cm *ConfigRollbackManager) CreateMainConfig(content []byte) (bool, error) {
	if cm.configVersion == 0 {
		nl.Debugf(cm.logger, "Skipping validation on first iteration (configVersion == 0)")
		return cm.LocalManager.CreateMainConfig(content)
	}

	return cm.createConfigWithRollback("nginx.conf", cm.mainConfFilename, content, true)
}

// CreateConfig creates a configuration file after validating it won't break nginx.
// If validation fails, attempts rollback to previous working config.
func (cm *ConfigRollbackManager) CreateConfig(name string, content []byte) (bool, error) {
	return cm.createConfigWithRollback(name, cm.getFilenameForConfig(name), content, false)
}

// CreateStreamConfig creates a stream configuration file after validating it won't break nginx.
// If validation fails, attempts rollback to previous working config.
func (cm *ConfigRollbackManager) CreateStreamConfig(name string, content []byte) bool {
	changed, err := cm.createConfigWithRollback(name, cm.getFilenameForStreamConfig(name), content, false)
	if err != nil {
		nl.Warnf(cm.logger, "CreateStreamConfig for %s failed: %v", name, err)
		return false
	}
	return changed
}
