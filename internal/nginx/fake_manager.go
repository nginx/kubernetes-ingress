package nginx

import (
	"log/slog"
	"net/http"
	"os"
	"path"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
	"github.com/nginx/nginx-plus-go-client/v3/client"
)

// FakeManager provides a fake implementation of the Manager interface.
type FakeManager struct {
	confdPath       string
	secretsPath     string
	dhparamFilename string
	logger          *slog.Logger
}

// NewFakeManager creates a FakeManager.
func NewFakeManager(confPath string) *FakeManager {
	return &FakeManager{
		confdPath:       path.Join(confPath, "conf.d"),
		secretsPath:     path.Join(confPath, "secrets"),
		dhparamFilename: path.Join(confPath, "secrets", "dhparam.pem"),
		logger:          slog.New(nic_glog.New(os.Stdout, &nic_glog.Options{Level: levels.LevelInfo})),
	}
}

// CreateMainConfig provides a fake implementation of CreateMainConfig.
func (fm *FakeManager) CreateMainConfig(content []byte) bool {
	nl.Debug(fm.logger, "Writing main config")
	nl.Debug(fm.logger, string(content))
	return true
}

// CreateConfig provides a fake implementation of CreateConfig.
func (fm *FakeManager) CreateConfig(name string, content []byte) bool {
	nl.Debugf(fm.logger, "Writing config %v", name)
	nl.Debug(fm.logger, string(content))
	return true
}

// CreateAppProtectResourceFile provides a fake implementation of CreateAppProtectResourceFile
func (fm *FakeManager) CreateAppProtectResourceFile(name string, content []byte) {
	nl.Debugf(fm.logger, "Writing Ap Resource File %v", name)
	nl.Debug(fm.logger, string(content))
}

// DeleteAppProtectResourceFile provides a fake implementation of DeleteAppProtectResourceFile
func (fm *FakeManager) DeleteAppProtectResourceFile(name string) {
	nl.Debugf(fm.logger, "Deleting Ap Resource File %v", name)
}

// ClearAppProtectFolder provides a fake implementation of ClearAppProtectFolder
func (fm *FakeManager) ClearAppProtectFolder(name string) {
	nl.Debugf(fm.logger, "Deleting Ap Resource folder %v", name)
}

// DeleteConfig provides a fake implementation of DeleteConfig.
func (fm *FakeManager) DeleteConfig(name string) {
	nl.Debugf(fm.logger, "Deleting config %v", name)
}

// CreateStreamConfig provides a fake implementation of CreateStreamConfig.
func (fm *FakeManager) CreateStreamConfig(name string, content []byte) bool {
	nl.Debugf(fm.logger, "Writing stream config %v", name)
	nl.Debug(fm.logger, string(content))
	return true
}

// DeleteStreamConfig provides a fake implementation of DeleteStreamConfig.
func (fm *FakeManager) DeleteStreamConfig(name string) {
	nl.Debugf(fm.logger, "Deleting stream config %v", name)
}

// CreateTLSPassthroughHostsConfig provides a fake implementation of CreateTLSPassthroughHostsConfig.
func (fm *FakeManager) CreateTLSPassthroughHostsConfig(_ []byte) bool {
	nl.Debugf(fm.logger, "Writing TLS Passthrough Hosts config file")
	return false
}

// CreateSecret provides a fake implementation of CreateSecret.
func (fm *FakeManager) CreateSecret(name string, _ []byte, _ os.FileMode) string {
	nl.Debugf(fm.logger, "Writing secret %v", name)
	return fm.GetFilenameForSecret(name)
}

// DeleteSecret provides a fake implementation of DeleteSecret.
func (fm *FakeManager) DeleteSecret(name string) {
	nl.Debugf(fm.logger, "Deleting secret %v", name)
}

// GetFilenameForSecret provides a fake implementation of GetFilenameForSecret.
func (fm *FakeManager) GetFilenameForSecret(name string) string {
	return path.Join(fm.secretsPath, name)
}

// CreateDHParam provides a fake implementation of CreateDHParam.
func (fm *FakeManager) CreateDHParam(_ string) (string, error) {
	nl.Debugf(fm.logger, "Writing dhparam file")
	return fm.dhparamFilename, nil
}

// Version provides a fake implementation of Version.
func (fm *FakeManager) Version() Version {
	nl.Debug(fm.logger, "Printing nginx version")
	return NewVersion("nginx version: nginx/1.25.3 (nginx-plus-r31)")
}

// Start provides a fake implementation of Start.
func (fm *FakeManager) Start(_ chan error) {
	nl.Debug(fm.logger, "Starting nginx")
}

// Reload provides a fake implementation of Reload.
func (fm *FakeManager) Reload(_ bool) error {
	nl.Debugf(fm.logger, "Reloading nginx")
	return nil
}

// Quit provides a fake implementation of Quit.
func (fm *FakeManager) Quit() {
	nl.Debug(fm.logger, "Quitting nginx")
}

// UpdateConfigVersionFile provides a fake implementation of UpdateConfigVersionFile.
func (fm *FakeManager) UpdateConfigVersionFile() {
	nl.Debugf(fm.logger, "Writing config version")
}

// SetPlusClients provides a fake implementation of SetPlusClients.
func (*FakeManager) SetPlusClients(_ *client.NginxClient, _ *http.Client) {
}

// UpdateServersInPlus provides a fake implementation of UpdateServersInPlus.
func (fm *FakeManager) UpdateServersInPlus(upstream string, servers []string, _ ServerConfig) error {
	nl.Debugf(fm.logger, "Updating servers of %v: %v", upstream, servers)
	return nil
}

// UpdateStreamServersInPlus provides a fake implementation of UpdateStreamServersInPlus.
func (fm *FakeManager) UpdateStreamServersInPlus(upstream string, servers []string) error {
	nl.Debugf(fm.logger, "Updating stream servers of %v: %v", upstream, servers)
	return nil
}

// AppProtectPluginStart is a fake implementation AppProtectPluginStart
func (fm *FakeManager) AppProtectPluginStart(_ chan error, _ string) {
	nl.Debugf(fm.logger, "Starting FakeAppProtectPlugin")
}

// AppProtectPluginQuit is a fake implementation AppProtectPluginQuit
func (fm *FakeManager) AppProtectPluginQuit() {
	nl.Debugf(fm.logger, "Quitting FakeAppProtectPlugin")
}

// AppProtectDosAgentQuit is a fake implementation AppProtectAgentQuit
func (fm *FakeManager) AppProtectDosAgentQuit() {
	nl.Debugf(fm.logger, "Quitting FakeAppProtectDosAgent")
}

// AppProtectDosAgentStart is a fake implementation of AppProtectAgentStart
func (fm *FakeManager) AppProtectDosAgentStart(_ chan error, _ bool, _ int, _ int, _ int) {
	nl.Debugf(fm.logger, "Starting FakeAppProtectDosAgent")
}

// AgentQuit is a fake implementation AppProtectAgentQuit
func (fm *FakeManager) AgentQuit() {
	nl.Debugf(fm.logger, "Quitting FakeAgent")
}

// AgentStart is a fake implementation of AppProtectAgentStart
func (fm *FakeManager) AgentStart(_ chan error, _ string) {
	nl.Debugf(fm.logger, "Starting FakeAgent")
}

// AgentVersion is a fake implementation of AppProtectAgentStart
func (fm *FakeManager) AgentVersion() string {
	return "v0.00.0-00000000"
}

// GetSecretsDir is a fake implementation
func (fm *FakeManager) GetSecretsDir() string {
	return fm.secretsPath
}

// UpsertSplitClientsKeyVal is a fake implementation of UpsertSplitClientsKeyVal
func (fm *FakeManager) UpsertSplitClientsKeyVal(_ string, _ string, _ string) {
	nl.Debugf(fm.logger, "Creating split clients key")
}

// DeleteKeyValStateFiles is a fake implementation of DeleteKeyValStateFiles
func (fm *FakeManager) DeleteKeyValStateFiles(_ string) {
	nl.Debugf(fm.logger, "Deleting keyval state files")
}
