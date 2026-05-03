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

// batchConfigEntry tracks a config file written during batch mode for potential rollback.
type batchConfigEntry struct {
	name       string
	configPath string
	backup     []byte
	hasBackup  bool
}

// ConfigRollbackManager wraps LocalManager and adds rollback protection for main and regular configs.
type ConfigRollbackManager struct {
	*LocalManager
	batchMode    bool
	batchConfigs []batchConfigEntry
}

// NewConfigRollbackManager creates a ConfigRollbackManager.
func NewConfigRollbackManager(ctx context.Context, confPath string, debug bool, mc collectors.ManagerCollector, lr *license_reporting.LicenseReporter, metadata *metadata.Metadata, timeout time.Duration, nginxPlus bool) *ConfigRollbackManager {
	lm := NewLocalManager(ctx, confPath, debug, mc, lr, metadata, timeout, nginxPlus)
	return &ConfigRollbackManager{LocalManager: lm}
}

// testConfig tests the nginx configuration for syntax errors and file accessibility.
func (cm *ConfigRollbackManager) testConfig() error {
	nl.Debugf(cm.logger, "Testing nginx configuration")

	if err := nginxTestError(cm.logger, cm.debug); err != nil {
		return err
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
			testErr := cm.testConfig()
			if testErr == nil {
				nl.Debugf(cm.logger, "Configuration %s is already applied and working", name)
				return false, nil
			}
			nl.Warnf(cm.logger, "Configuration %s was already validated and found invalid: %v", name, testErr)
			return false, fmt.Errorf("configuration %s was already validated and found invalid: %w", name, testErr)
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
				return false, fmt.Errorf("configuration validation failed for %s, rolled back to previous working config: %w", name, err)
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
// In batch mode, writes the file without per-file validation.
func (cm *ConfigRollbackManager) CreateConfig(name string, content []byte) (bool, error) {
	if cm.batchMode {
		return cm.batchWriteConfig(name, cm.getFilenameForConfig(name), content)
	}
	return cm.createConfigWithRollback(name, cm.getFilenameForConfig(name), content, false)
}

// CreateStreamConfig creates a stream configuration file after validating it won't break nginx.
// If validation fails, attempts rollback to previous working config.
// In batch mode, writes the file without per-file validation.
func (cm *ConfigRollbackManager) CreateStreamConfig(name string, content []byte) (bool, error) {
	if cm.batchMode {
		return cm.batchWriteConfig(name, cm.getFilenameForStreamConfig(name), content)
	}
	return cm.createConfigWithRollback(name, cm.getFilenameForStreamConfig(name), content, false)
}

// EnableBatchMode enables deferred validation. Configs written via CreateConfig/CreateStreamConfig
// will be written to disk without per-file nginx -t testing. Call CompleteBatch to validate all
// configs with a single nginx -t test, falling back to per-file validation on failure.
func (cm *ConfigRollbackManager) EnableBatchMode() {
	nl.Debugf(cm.logger, "Enabling batch config mode for deferred validation")
	cm.batchMode = true
	cm.batchConfigs = nil
}

// CompleteBatch validates all batch-written configs with a single nginx -t test.
// On success, clears batch state and returns nil. On failure, restores all backups
// (or deletes new files) and returns the validation error. Batch mode is always
// disabled after this call regardless of outcome.
func (cm *ConfigRollbackManager) CompleteBatch() error {
	cm.batchMode = false

	if len(cm.batchConfigs) == 0 {
		nl.Debugf(cm.logger, "No configs written during batch mode, skipping validation")
		cm.batchConfigs = nil
		return nil
	}

	nl.Debugf(cm.logger, "Validating %d batch-written configs with single nginx -t test", len(cm.batchConfigs))

	if err := cm.testConfig(); err != nil {
		nl.Warnf(cm.logger, "Batch validation failed for %d configs: %v. Restoring backups.", len(cm.batchConfigs), err)
		cm.rollbackBatch()
		return err
	}

	nl.Debugf(cm.logger, "Batch validation passed for %d configs", len(cm.batchConfigs))
	cm.batchConfigs = nil
	return nil
}

// batchWriteConfig writes a config file without nginx -t validation, tracking it for
// potential rollback. Existing file content is backed up before overwriting.
func (cm *ConfigRollbackManager) batchWriteConfig(name, configPath string, content []byte) (bool, error) {
	entry := batchConfigEntry{
		name:       name,
		configPath: configPath,
	}

	// #nosec G304 -- configPath is constructed from safe internal paths
	if existingContent, readErr := os.ReadFile(configPath); readErr == nil {
		if bytes.Equal(existingContent, content) {
			nl.Debugf(cm.logger, "Batch mode: config %s unchanged, skipping write", name)
			return false, nil
		}
		entry.backup = existingContent
		entry.hasBackup = true
	}

	nl.Debugf(cm.logger, "Batch mode: writing config %s to %v (deferred validation)", name, configPath)
	if err := createFileAndWrite(configPath, content); err != nil {
		nl.Fatalf(cm.logger, "Failed to write config to %v: %v", configPath, err)
	}

	cm.batchConfigs = append(cm.batchConfigs, entry)
	return true, nil
}

// rollbackBatch restores all configs written during batch mode to their previous state.
func (cm *ConfigRollbackManager) rollbackBatch() {
	for _, entry := range cm.batchConfigs {
		if entry.hasBackup {
			nl.Debugf(cm.logger, "Restoring backup for %s", entry.name)
			if err := createFileAndWrite(entry.configPath, entry.backup); err != nil {
				nl.Errorf(cm.logger, "Failed to restore backup for %s: %v", entry.name, err)
			}
		} else {
			nl.Debugf(cm.logger, "Removing new config %s (no previous backup)", entry.name)
			deleteConfig(cm.logger, entry.configPath)
		}
	}
	cm.batchConfigs = nil
}
