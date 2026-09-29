package nginx

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
)

// newTestRollbackManager constructs a minimally-wired ConfigRollbackManager rooted at a
// temp confPath. It exercises only excludeConfig / EnableBatchMode paths — callers that
// need testConfig, Reload, or LocalManager helpers must set up more state.
func newTestRollbackManager(t *testing.T) (*ConfigRollbackManager, string) {
	t.Helper()
	confPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(confPath, "conf.d"), 0o750); err != nil {
		t.Fatalf("mkdir conf.d: %v", err)
	}
	lm := &LocalManager{
		confdPath:                 filepath.Join(confPath, "conf.d"),
		defaultServerConfFilename: filepath.Join(confPath, "conf.d", "_default-server.conf"),
		logger:                    slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo})),
	}
	cm := &ConfigRollbackManager{
		LocalManager: lm,
		batchFiles:   make(map[string]string),
	}
	return cm, confPath
}

func TestEnableBatchMode_SnapshotsExistingDefaultServer(t *testing.T) {
	t.Parallel()
	cm, _ := newTestRollbackManager(t)
	bootstrap := []byte("server { server_name _; return 404; }\n")
	if err := os.WriteFile(cm.defaultServerConfFilename, bootstrap, 0o600); err != nil {
		t.Fatalf("seed default server: %v", err)
	}

	cm.EnableBatchMode()

	if !bytes.Equal(cm.preBatchDefaultServer, bootstrap) {
		t.Fatalf("preBatchDefaultServer snapshot mismatch:\ngot:  %q\nwant: %q", cm.preBatchDefaultServer, bootstrap)
	}
}

func TestEnableBatchMode_MissingDefaultServer_LeavesSnapshotNil(t *testing.T) {
	t.Parallel()
	cm, _ := newTestRollbackManager(t)

	cm.EnableBatchMode()

	if cm.preBatchDefaultServer != nil {
		t.Fatalf("expected preBatchDefaultServer to be nil when file absent, got %q", cm.preBatchDefaultServer)
	}
}

func TestExcludeConfig_DefaultServer_RestoresPreBatchSnapshot(t *testing.T) {
	t.Parallel()
	cm, _ := newTestRollbackManager(t)
	bootstrap := []byte("server { server_name _; return 404; }\n")
	if err := os.WriteFile(cm.defaultServerConfFilename, bootstrap, 0o600); err != nil {
		t.Fatalf("seed default server: %v", err)
	}
	cm.EnableBatchMode()

	// Simulate a bad empty-host Ingress overwriting the shared default server.
	badContent := []byte("server { proxy_busy_buffers_size garbage; }\n")
	if err := os.WriteFile(cm.defaultServerConfFilename, badContent, 0o600); err != nil {
		t.Fatalf("overwrite default server: %v", err)
	}
	cm.batchFiles[cm.defaultServerConfFilename] = "_default-server"

	err := cm.excludeConfig(cm.defaultServerConfFilename, "_default-server", errors.New("nginx: [emerg] invalid value"))
	if err != nil {
		t.Fatalf("excludeConfig returned unexpected error: %v", err)
	}

	restored, readErr := os.ReadFile(cm.defaultServerConfFilename)
	if readErr != nil {
		t.Fatalf("default server file missing after restore: %v", readErr)
	}
	if !bytes.Equal(restored, bootstrap) {
		t.Fatalf("default server content not restored:\ngot:  %q\nwant: %q", restored, bootstrap)
	}
	if _, tracked := cm.batchFiles[cm.defaultServerConfFilename]; tracked {
		t.Fatalf("expected %s to be removed from batchFiles after exclusion", cm.defaultServerConfFilename)
	}
	if len(cm.batchExcluded) != 1 || cm.batchExcluded[0].ConfigPath != cm.defaultServerConfFilename {
		t.Fatalf("expected one recorded exclusion for default-server, got %+v", cm.batchExcluded)
	}
}

func TestExcludeConfig_DefaultServer_NoSnapshot_FallsBackToRemove(t *testing.T) {
	t.Parallel()
	cm, _ := newTestRollbackManager(t)
	// Skip EnableBatchMode — snapshot stays nil.
	badContent := []byte("server { bad; }\n")
	if err := os.WriteFile(cm.defaultServerConfFilename, badContent, 0o600); err != nil {
		t.Fatalf("write default server: %v", err)
	}
	cm.batchFiles[cm.defaultServerConfFilename] = "_default-server"

	err := cm.excludeConfig(cm.defaultServerConfFilename, "_default-server", errors.New("nginx: [emerg] bad"))
	if err != nil {
		t.Fatalf("excludeConfig returned unexpected error: %v", err)
	}

	if _, statErr := os.Stat(cm.defaultServerConfFilename); !os.IsNotExist(statErr) {
		t.Fatalf("expected default server file to be removed when no snapshot exists, stat err=%v", statErr)
	}
}

func TestExcludeConfig_RegularFile_IsAlwaysDeleted(t *testing.T) {
	t.Parallel()
	cm, confPath := newTestRollbackManager(t)
	// Seed a snapshot for the default-server path to prove the restore path is not
	// entered for other files.
	cm.preBatchDefaultServer = []byte("bootstrap")

	regular := filepath.Join(confPath, "conf.d", "namespace-name.conf")
	if err := os.WriteFile(regular, []byte("server { bad; }"), 0o600); err != nil {
		t.Fatalf("write regular config: %v", err)
	}
	cm.batchFiles[regular] = "namespace-name"

	err := cm.excludeConfig(regular, "namespace-name", errors.New("nginx: [emerg] bad"))
	if err != nil {
		t.Fatalf("excludeConfig returned unexpected error: %v", err)
	}

	if _, statErr := os.Stat(regular); !os.IsNotExist(statErr) {
		t.Fatalf("expected regular config file to be removed, stat err=%v", statErr)
	}
	if _, tracked := cm.batchFiles[regular]; tracked {
		t.Fatalf("expected %s to be removed from batchFiles after exclusion", regular)
	}
}
