package nginx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	license_reporting "github.com/nginx/kubernetes-ingress/internal/license_reporting"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/metadata"
	"github.com/nginx/kubernetes-ingress/internal/metrics/collectors"
)

const (
	// disabledSuffix is appended to config files during binary search isolation.
	// NGINX include globs (*.conf) do not match this suffix, making files invisible to nginx -t.
	disabledSuffix = ".conf.disabled"
)

// nginxTestPathRe extracts file paths from nginx -t error output.
// nginx -t reports errors like:
//
//	nginx: [emerg] invalid value "x" in /etc/nginx/conf.d/default-cafe.conf:21
//	nginx: [emerg] open() "/etc/nginx/secrets/foo" failed (2: No such file or directory)
var nginxTestPathRe = regexp.MustCompile(`/etc/nginx/[^\s:"']+`)

// BatchExclusion records a config file excluded during batch validation, along
// with the resource it belongs to and the nginx -t error that caused exclusion.
type BatchExclusion struct {
	ConfigPath   string
	ResourceName string
	Error        error
}

// ConfigRollbackManager wraps LocalManager and adds rollback protection for main and regular configs.
// In batch mode (startup), it writes configs without per-file nginx -t validation, deferring
// validation to a single CompleteBatch() call that tests the entire config tree at once.
type ConfigRollbackManager struct {
	*LocalManager
	initialDefaultServerPending bool

	// batchMode indicates that config writes should skip per-file nginx -t validation.
	// Enabled during startup to avoid O(N²) validation cost.
	batchMode bool

	// batchFiles maps absolute config file path → resource name for files written during batch mode.
	// Used for failure attribution: when nginx -t fails, we parse the offending path from stderr
	// and look it up here to identify which resource to exclude.
	batchFiles map[string]string

	// batchExcluded tracks resources removed during failure isolation in CompleteBatch.
	// After batch completes, this is returned to the caller for logging and event reporting.
	batchExcluded []BatchExclusion

	// preBatchDefaultServer holds the on-disk contents of _default-server.conf captured
	// when batch mode is enabled. If a bad empty-host Ingress overwrites the shared
	// default-server file during batch mode and isolation excludes it, excludeConfig
	// restores this snapshot instead of leaving the file missing.
	preBatchDefaultServer []byte
}

// NewConfigRollbackManager creates a ConfigRollbackManager.
func NewConfigRollbackManager(ctx context.Context, confPath string, debug bool, mc collectors.ManagerCollector, lr *license_reporting.LicenseReporter, metadata *metadata.Metadata, timeout time.Duration, nginxPlus bool) *ConfigRollbackManager {
	lm := NewLocalManager(ctx, confPath, debug, mc, lr, metadata, timeout, nginxPlus)
	return &ConfigRollbackManager{
		LocalManager:                lm,
		initialDefaultServerPending: true,
		batchFiles:                  make(map[string]string),
	}
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
// Protected configs (main config and default server) are never deleted on failure.
func (cm *ConfigRollbackManager) createConfigWithRollback(name string, configPath string, content []byte) (bool, error) {
	protectFromDeletion := configPath == cm.mainConfFilename || configPath == cm.defaultServerConfFilename
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
				if !protectFromDeletion {
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
			if !protectFromDeletion {
				deleteConfig(cm.logger, configPath)
			}
			return false, fmt.Errorf("configuration validation failed and rollback didn't resolve issues for %s: %w", name, err)
		}

		nl.Warnf(cm.logger, "No previous config to rollback to for %s", name)
		if !protectFromDeletion {
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

	return cm.createConfigWithRollback("nginx.conf", cm.mainConfFilename, content)
}

// CreateConfig creates a configuration file after validating it won't break nginx.
// If validation fails, attempts rollback to previous working config.
// In batch mode, writes directly and records the file for deferred validation.
func (cm *ConfigRollbackManager) CreateConfig(name string, content []byte) (bool, error) {
	configPath := cm.getFilenameForConfig(name)
	if cm.initialDefaultServerPending && configPath == cm.defaultServerConfFilename {
		cm.initialDefaultServerPending = false
		nl.Debugf(cm.logger, "Skipping validation for initial default server config bootstrap")
		return cm.LocalManager.CreateConfig(name, content)
	}

	if cm.batchMode {
		return cm.batchWriteConfig(name, configPath, content)
	}

	return cm.createConfigWithRollback(name, configPath, content)
}

// CreateStreamConfig creates a stream configuration file after validating it won't break nginx.
// If validation fails, attempts rollback to previous working config.
// In batch mode, writes directly and records the file for deferred validation.
func (cm *ConfigRollbackManager) CreateStreamConfig(name string, content []byte) (bool, error) {
	configPath := cm.getFilenameForStreamConfig(name)

	if cm.batchMode {
		return cm.batchWriteConfig(name, configPath, content)
	}

	return cm.createConfigWithRollback(name, configPath, content)
}

// --- Batch mode methods ---
// These methods implement startup batch validation: write all configs without per-file
// nginx -t, then validate the entire tree with a single test, isolating bad configs on failure.

// EnableBatchMode activates deferred validation. All subsequent CreateConfig/CreateStreamConfig
// calls will write files directly without running nginx -t. Call CompleteBatch() to validate
// the entire config tree with a single nginx -t test.
//
// This should only be called during startup before the queue begins processing.
func (cm *ConfigRollbackManager) EnableBatchMode() {
	nl.Debugf(cm.logger, "Enabling batch config mode for deferred validation")
	cm.batchMode = true
	cm.batchFiles = make(map[string]string)
	cm.batchExcluded = nil

	// Snapshot the bootstrap synthetic _default-server.conf written by main.go before any
	// empty-host Ingress can overwrite it in batch mode. If that batch entry is later
	// excluded during isolation, excludeConfig restores this snapshot instead of deleting
	// the file, keeping port 80/443 responsive to unmatched hosts.
	cm.preBatchDefaultServer = nil
	// #nosec G304 -- defaultServerConfFilename is a constant NIC-owned path
	if snapshot, err := os.ReadFile(cm.defaultServerConfFilename); err == nil {
		cm.preBatchDefaultServer = snapshot
	} else if !os.IsNotExist(err) {
		nl.Warnf(cm.logger, "Batch mode: could not snapshot %s for restore-on-exclusion: %v", cm.defaultServerConfFilename, err)
	}
}

// IsBatchMode returns whether the manager is currently in batch mode.
func (cm *ConfigRollbackManager) IsBatchMode() bool {
	return cm.batchMode
}

// TestConfig runs a single `nginx -t` and returns any error from NGINX.
// Exposed for callers that need to probe the on-disk config state directly
// (e.g., after batch cleanup, to decide whether per-file replay can succeed).
func (cm *ConfigRollbackManager) TestConfig() error {
	return cm.testConfig()
}

// BatchExclusions returns the list of resources excluded during CompleteBatch isolation.
// Returns nil if no exclusions occurred.
func (cm *ConfigRollbackManager) BatchExclusions() []BatchExclusion {
	return cm.batchExcluded
}

// batchWriteConfig writes a config file without per-file nginx -t validation.
// If the file already exists with identical content, the write is skipped entirely.
// The file path and resource name are recorded in batchFiles for failure attribution.
func (cm *ConfigRollbackManager) batchWriteConfig(name, configPath string, content []byte) (bool, error) {
	// Skip write if content is byte-identical to what's already on disk.
	// The existing content (if any) was either written earlier in this batch or
	// is left over from a previous pod lifecycle — either way, if it matches,
	// there's nothing new to write or validate.
	// #nosec G304 -- configPath is constructed from safe internal paths
	if existingContent, readErr := os.ReadFile(configPath); readErr == nil {
		if bytes.Equal(existingContent, content) {
			nl.Debugf(cm.logger, "Batch mode: config %s unchanged, skipping write", name)
			// Still record it in batchFiles so CompleteBatch validates it as part of the tree
			cm.batchFiles[configPath] = name
			return false, nil
		}
	}

	nl.Debugf(cm.logger, "Batch mode: writing config %s to %v (deferred validation)", name, configPath)
	if err := createFileAndWrite(configPath, content); err != nil {
		nl.Fatalf(cm.logger, "Failed to write config to %v: %v", configPath, err)
	}

	cm.batchFiles[configPath] = name
	return true, nil
}

// CompleteBatch validates all batch-written configs with a single nginx -t test.
// On success, clears batch state and returns nil and the caller should proceed to reload.
// On failure, attempts to isolate and exclude bad configs via two-tier isolation:
//   - Tier 1: Parse file path from nginx -t error output (direct attribution)
//   - Tier 2: Binary search over candidate files when path is not parseable
//
// Returns an error only if isolation completely fails (nuclear fallback needed).
// Batch mode is always disabled after this call regardless of outcome.
//
// The full-tree nginx -t is run unconditionally, even when batchFiles is empty.
func (cm *ConfigRollbackManager) CompleteBatch() error {
	cm.batchMode = false

	nl.Infof(cm.logger, "Validating batch state with single nginx -t test (%d batch-tracked configs)", len(cm.batchFiles))

	// Run a single full-tree nginx -t. This is the happy path: O(N) cost for N files.
	if err := cm.testConfig(); err == nil {
		nl.Infof(cm.logger, "Batch validation passed (%d configs tracked)", len(cm.batchFiles))
		cm.batchFiles = make(map[string]string)
		return nil
	}

	// Validation failed — enter isolation loop to identify and exclude bad config(s).
	nl.Warnf(cm.logger, "Batch validation failed, entering isolation to identify bad config(s)")
	if err := cm.isolateBadConfigs(); err != nil {
		// Nuclear fallback: could not isolate. Delete all batch files and return error.
		// Caller should fall back to per-file validation (today's slow but correct path).
		nl.Errorf(cm.logger, "Failed to isolate bad configs, removing all %d batch configs: %v", len(cm.batchFiles), err)
		cm.removeAllBatchFiles()
		return fmt.Errorf("batch validation failed and isolation could not converge: %w", err)
	}

	// Isolation succeeded — some configs were excluded but the remaining tree is valid.
	nl.Infof(cm.logger, "Batch isolation complete: %d config(s) excluded, remaining tree is valid", len(cm.batchExcluded))
	cm.batchFiles = make(map[string]string)
	return nil
}

// isolateBadConfigs implements two-tier failure isolation:
//  1. Direct attribution: parse file path from nginx -t stderr, delete that file, re-test
//  2. Binary search: if path cannot be parsed, bisect the candidate set to find the bad file
//
// Uses a progress-based loop: continues as long as each iteration removes at least
// one bad file. Termination is guaranteed because the batch file set is finite and
// each iteration strictly reduces it. The loop exits when:
//   - nginx -t passes (success)
//   - no candidates remain but nginx -t still fails (non-batch file issue)
//   - binary search cannot isolate (interaction failure between files)
//   - excludeConfig fails (file system error — escalate to nuclear fallback)
//   - the iteration cap is exceeded (defensive belt-and-suspenders; should be unreachable)
func (cm *ConfigRollbackManager) isolateBadConfigs() error {
	// Defensive cap: N deletions plus a small margin for binary search rounds.
	// Progress is normally guaranteed by the strictly-decreasing batchFiles map,
	// but if a file system anomaly leaves stale state, this cap prevents an
	// unbounded loop from consuming CPU indefinitely.
	maxIterations := len(cm.batchFiles) + 10
	for iter := 0; iter < maxIterations; iter++ {
		testErr := cm.testConfig()
		if testErr == nil {
			// Tree is now valid with remaining configs
			return nil
		}

		// Tier 1: Try direct attribution from nginx -t error output
		badPath := cm.parsePathFromError(testErr)
		if badPath != "" {
			if resourceName, tracked := cm.batchFiles[badPath]; tracked {
				nl.Warnf(cm.logger, "Batch isolation: removing bad config %s (%s): %v", badPath, resourceName, testErr)
				if err := cm.excludeConfig(badPath, resourceName, testErr); err != nil {
					return fmt.Errorf("isolation aborted, cannot exclude %s: %w", badPath, err)
				}
				continue
			}
			// Path was found in error but not in our batch set and might be main config or
			// a file we didn't write. Can't attribute, fall through to binary search.
		}

		// Tier 2: Binary search over remaining candidates
		nl.Debugf(cm.logger, "Batch isolation: no attributable path in error, attempting binary search")
		candidates := cm.candidatePaths()
		if len(candidates) == 0 {
			return fmt.Errorf("no candidates remaining but nginx -t still fails: %w", testErr)
		}

		badFile, searchErr := cm.binarySearchBadConfig(candidates)
		if searchErr != nil {
			return fmt.Errorf("binary search could not isolate bad config: %w", searchErr)
		}

		resourceName := cm.batchFiles[badFile]
		nl.Warnf(cm.logger, "Batch isolation (binary search): removing bad config %s (%s)", badFile, resourceName)
		if err := cm.excludeConfig(badFile, resourceName, testErr); err != nil {
			return fmt.Errorf("isolation aborted, cannot exclude %s: %w", badFile, err)
		}
	}
	return fmt.Errorf("isolation exceeded iteration cap of %d — file system state may be inconsistent", maxIterations)
}

// parsePathFromError extracts the first /etc/nginx/* file path from an nginx -t error string.
// Returns empty string if no matching path is found.
func (cm *ConfigRollbackManager) parsePathFromError(err error) string {
	matches := nginxTestPathRe.FindAllString(err.Error(), -1)
	for _, raw := range matches {
		// Strip trailing punctuation that may be captured (commas, periods, closing parens)
		path := strings.TrimRight(raw, ".,;)")
		// Only consider conf.d/ and stream-conf.d/ files that we track
		if _, tracked := cm.batchFiles[path]; tracked {
			return path
		}
	}
	return ""
}

// binarySearchBadConfig uses binary search to isolate a bad config file when nginx -t
// error output does not contain a parseable path. Works by temporarily disabling halves
// of the candidate set (renaming *.conf to *.conf.disabled) and re-testing.
//
// This works because NIC-generated configs are self-contained: each has its own
// server{} + upstream{} blocks with no cross-file dependencies.
func (cm *ConfigRollbackManager) binarySearchBadConfig(candidates []string) (string, error) {
	if len(candidates) == 0 {
		return "", fmt.Errorf("empty candidate set")
	}
	if len(candidates) == 1 {
		// Base case: single candidate must be the bad one
		return candidates[0], nil
	}

	mid := len(candidates) / 2
	secondHalf := candidates[mid:]

	// Temporarily disable the second half by renaming files so NGINX's include glob won't match them
	cm.disableConfigs(secondHalf)

	// Test with only the first half active
	testErr := cm.testConfig()

	// Restore the second half regardless of test result
	cm.enableConfigs(secondHalf)

	if testErr == nil {
		// First half is clean — bad file is in the second half
		return cm.binarySearchBadConfig(secondHalf)
	}
	// First half contains (at least one) bad file
	return cm.binarySearchBadConfig(candidates[:mid])
}

// disableConfigs renames config files by replacing .conf suffix with .conf.disabled,
// making them invisible to NGINX's include *.conf glob patterns.
func (cm *ConfigRollbackManager) disableConfigs(paths []string) {
	for _, p := range paths {
		disabled := strings.TrimSuffix(p, ".conf") + disabledSuffix
		if err := os.Rename(p, disabled); err != nil {
			nl.Warnf(cm.logger, "Failed to disable config %s: %v", p, err)
		}
	}
}

// enableConfigs restores previously disabled configs by renaming .conf.disabled back to .conf.
func (cm *ConfigRollbackManager) enableConfigs(paths []string) {
	for _, p := range paths {
		disabled := strings.TrimSuffix(p, ".conf") + disabledSuffix
		if err := os.Rename(disabled, p); err != nil {
			nl.Warnf(cm.logger, "Failed to re-enable config %s: %v", p, err)
		}
	}
}

// excludeConfig removes a bad config file and records it as an excluded resource.
//
// For the shared _default-server.conf, the pre-batch snapshot captured in EnableBatchMode
// is written back in place of the delete so nginx still has a valid default server after
// an empty-host Ingress is excluded. For every other file, the delete is unconditional.
//
// Returns an error when the file cannot be removed (or restored). Silently continuing
// would leave the bad content on disk while dropping the file from batchFiles tracking,
// which cascades into false attribution during subsequent isolation iterations. Callers
// must treat this error as a signal to escalate to nuclear fallback.
func (cm *ConfigRollbackManager) excludeConfig(configPath, resourceName string, reason error) error {
	if configPath == cm.defaultServerConfFilename && cm.preBatchDefaultServer != nil {
		if err := createFileAndWrite(configPath, cm.preBatchDefaultServer); err != nil {
			return fmt.Errorf("failed to restore pre-batch default server config %s: %w", configPath, err)
		}
		nl.Infof(cm.logger, "Batch isolation: restored pre-batch %s after excluding %s", configPath, resourceName)
	} else {
		if err := os.Remove(configPath); err != nil {
			return fmt.Errorf("failed to remove excluded config %s: %w", configPath, err)
		}
	}
	cm.batchExcluded = append(cm.batchExcluded, BatchExclusion{
		ConfigPath:   configPath,
		ResourceName: resourceName,
		Error:        reason,
	})
	delete(cm.batchFiles, configPath)
	return nil
}

// removeAllBatchFiles deletes every file recorded in batchFiles. Used by the
// nuclear-fallback path when isolation cannot converge; the caller then either
// re-writes each resource individually via createConfigWithRollback (foundation
// intact) or gives up (foundation still bad after this).
func (cm *ConfigRollbackManager) removeAllBatchFiles() {
	for configPath, name := range cm.batchFiles {
		nl.Debugf(cm.logger, "Removing batch file %s (%s) for nuclear fallback", configPath, name)
		if err := os.Remove(configPath); err != nil {
			nl.Warnf(cm.logger, "Failed to remove batch file %s: %v", configPath, err)
		}
	}
	cm.batchFiles = make(map[string]string)
}

// candidatePaths returns a slice of all remaining batch file paths.
// Used as input for binary search isolation.
func (cm *ConfigRollbackManager) candidatePaths() []string {
	paths := make([]string, 0, len(cm.batchFiles))
	for p := range cm.batchFiles {
		paths = append(paths, p)
	}
	return paths
}
