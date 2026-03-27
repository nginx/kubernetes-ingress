package nginx

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path"
	"time"

	pb "github.com/nginx/agent/v3/api/grpc/mpi/v1"
	"github.com/nginx/nginx-plus-go-client/v3/client"
	"google.golang.org/protobuf/types/known/structpb"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/metrics/collectors"
	"github.com/nginx/kubernetes-ingress/internal/nginx/agent"
	"github.com/nginx/kubernetes-ingress/internal/nginx/agent/broadcast"
	agentgrpc "github.com/nginx/kubernetes-ingress/internal/nginx/agent/grpc"
)

const (
	agentConfPath              = "/etc/nginx"
	agentSecretsPath           = "/etc/nginx/secrets" //nolint:gosec // G101: not a credential, just a directory path
	agentConfdPath             = "/etc/nginx/conf.d"
	agentStreamConfdPath       = "/etc/nginx/stream-conf.d"
	agentOIDCConfPath          = "/etc/nginx/oidc-conf.d"
	agentMainConfFilename      = "/etc/nginx/nginx.conf"
	agentConfigVersionFilename = "/etc/nginx/config-version.conf"
	agentTLSPassthroughFn      = "/etc/nginx/tls-passthrough-hosts.conf" //nolint:gosec // G101: not a credential, config file path
	agentDhparamFilename       = "/etc/nginx/secrets/dhparam.pem"
)

// AgentManager implements the Manager interface using nginx-agent over gRPC MPI
// instead of direct file I/O and process management. It stores config files
// in-memory and pushes them to the agent via ConfigApplyRequest on Reload().
//
// Architecture: NIC controller runs in one container, nginx + nginx-agent in
// another container in the same pod. They communicate over a Unix socket.
type AgentManager struct {
	fileStore             *agent.FileStore
	broadcaster           broadcast.Broadcaster
	connTracker           agentgrpc.ConnectionsTracker
	grpcServer            *agentgrpc.Server
	verifyConfigGenerator *verifyConfigGenerator
	metricsCollector      collectors.ManagerCollector
	plusClient            *client.NginxClient
	logger                *slog.Logger
	configVersion         int
	nginxPlus             bool
}

// NewAgentManager creates a new AgentManager using Unix socket transport.
// Requires the nginx-agent unix socket patch (feature/unix-socket-support).
func NewAgentManager(
	ctx context.Context,
	mc collectors.ManagerCollector,
	nginxPlus bool,
) *AgentManager {
	return newAgentManager(ctx, mc, nginxPlus, nil)
}

// NewTLSAgentManager creates a new AgentManager using TCP+TLS transport.
// Works with the unmodified nginx-agent using standard host/port/TLS config.
// Cert, key, and CA are loaded from a Kubernetes Secret mounted into the pod.
func NewTLSAgentManager(
	ctx context.Context,
	mc collectors.ManagerCollector,
	nginxPlus bool,
	tlsConfig *agentgrpc.TLSConfig,
) *AgentManager {
	return newAgentManager(ctx, mc, nginxPlus, tlsConfig)
}

// newAgentManager constructs the AgentManager with the appropriate gRPC server.
// tlsConfig == nil means Unix socket mode; tlsConfig != nil means TCP+TLS mode.
func newAgentManager(
	ctx context.Context,
	mc collectors.ManagerCollector,
	nginxPlus bool,
	tlsConfig *agentgrpc.TLSConfig,
) *AgentManager {
	l := nl.LoggerFromContext(ctx)

	connTracker := agentgrpc.NewConnectionsTracker()
	fileStore := agent.NewFileStore()
	bcast := broadcast.NewNginxBroadcaster(ctx)

	cmdSvc := agent.NewCommandService(l, fileStore, connTracker, bcast)
	fileSvc := agent.NewFileService(l, fileStore, connTracker)

	svcs := agent.RegisterServices(cmdSvc, fileSvc)

	var grpcServer *agentgrpc.Server
	if tlsConfig != nil {
		grpcServer = agentgrpc.NewTLSServer(l, agentgrpc.DefaultTLSPort, tlsConfig, svcs)
	} else {
		grpcServer = agentgrpc.NewServer(l, agentgrpc.SocketPath, svcs)
	}

	vcg, err := newVerifyConfigGenerator()
	if err != nil {
		nl.Fatalf(l, "Error creating config version generator: %v", err)
	}

	return &AgentManager{
		fileStore:             fileStore,
		broadcaster:           bcast,
		connTracker:           connTracker,
		grpcServer:            grpcServer,
		verifyConfigGenerator: vcg,
		metricsCollector:      mc,
		logger:                l,
		nginxPlus:             nginxPlus,
	}
}

// CreateMainConfig stores the main NGINX configuration file.
func (am *AgentManager) CreateMainConfig(content []byte) (bool, error) {
	nl.Debugf(am.logger, "Storing main config in agent file store")
	changed := am.fileStore.Set(agentMainConfFilename, content)
	return changed, nil
}

// CreateConfig stores a configuration file for the conf.d directory.
func (am *AgentManager) CreateConfig(name string, content []byte) (bool, error) {
	filename := path.Join(agentConfdPath, name+".conf")
	nl.Debugf(am.logger, "Storing config in agent file store: %s", filename)
	changed := am.fileStore.Set(filename, content)
	return changed, nil
}

// DeleteConfig removes a configuration file from the conf.d directory.
func (am *AgentManager) DeleteConfig(name string) {
	filename := path.Join(agentConfdPath, name+".conf")
	nl.Debugf(am.logger, "Deleting config from agent file store: %s", filename)
	am.fileStore.Delete(filename)
}

// CreateStreamConfig stores a configuration file for the stream-conf.d directory.
func (am *AgentManager) CreateStreamConfig(name string, content []byte) (bool, error) {
	filename := path.Join(agentStreamConfdPath, name+".conf")
	nl.Debugf(am.logger, "Storing stream config in agent file store: %s", filename)
	changed := am.fileStore.Set(filename, content)
	return changed, nil
}

// DeleteStreamConfig removes a configuration file from stream-conf.d.
func (am *AgentManager) DeleteStreamConfig(name string) {
	filename := path.Join(agentStreamConfdPath, name+".conf")
	nl.Debugf(am.logger, "Deleting stream config from agent file store: %s", filename)
	am.fileStore.Delete(filename)
}

// CreateTLSPassthroughHostsConfig stores the TLS passthrough hosts config.
func (am *AgentManager) CreateTLSPassthroughHostsConfig(content []byte) bool {
	return am.fileStore.Set(agentTLSPassthroughFn, content)
}

// CreateOIDCConfig stores an OIDC configuration file.
func (am *AgentManager) CreateOIDCConfig(name string, content []byte) bool {
	filename := path.Join(agentOIDCConfPath, name+".conf")
	return am.fileStore.Set(filename, content)
}

// DeleteOIDCConfig removes an OIDC configuration file.
func (am *AgentManager) DeleteOIDCConfig(name string) {
	filename := path.Join(agentOIDCConfPath, name+".conf")
	am.fileStore.Delete(filename)
}

// CreateSecret stores a secret file in the agent file store.
func (am *AgentManager) CreateSecret(name string, content []byte, _ os.FileMode) string {
	filename := am.GetFilenameForSecret(name)
	nl.Debugf(am.logger, "Storing secret in agent file store: %s", filename)
	am.fileStore.Set(filename, content)
	return filename
}

// DeleteSecret removes a secret file from the agent file store.
func (am *AgentManager) DeleteSecret(name string) {
	filename := am.GetFilenameForSecret(name)
	nl.Debugf(am.logger, "Deleting secret from agent file store: %s", filename)
	am.fileStore.Delete(filename)
}

// GetFilenameForSecret constructs the filename for a secret.
func (am *AgentManager) GetFilenameForSecret(name string) string {
	return path.Join(agentSecretsPath, name)
}

// CreateDHParam stores the DH parameters file.
func (am *AgentManager) CreateDHParam(content string) (string, error) {
	am.fileStore.Set(agentDhparamFilename, []byte(content))
	return agentDhparamFilename, nil
}

// CreateAppProtectResourceFile is a no-op in agent mode (AppProtect deferred).
func (am *AgentManager) CreateAppProtectResourceFile(name string, _ []byte) {
	nl.Debugf(am.logger, "AppProtect resource file creation not supported in agent mode: %s", name)
}

// DeleteAppProtectResourceFile is a no-op in agent mode.
func (am *AgentManager) DeleteAppProtectResourceFile(name string) {
	nl.Debugf(am.logger, "AppProtect resource file deletion not supported in agent mode: %s", name)
}

// ClearAppProtectFolder is a no-op in agent mode.
func (am *AgentManager) ClearAppProtectFolder(_ string) {}

const agentConnectTimeout = 60 * time.Second

// Start launches the gRPC server and blocks until the nginx-agent connects
// and subscribes. If the agent does not connect within agentConnectTimeout,
// a fatal error is sent on the done channel which causes NIC to exit.
// This prevents the pod from accepting traffic with an unconfigured nginx.
//
// NGINX itself is started by the nginx container's entrypoint, not by NIC.
func (am *AgentManager) Start(done chan error) {
	go func() {
		nl.Infof(am.logger, "Starting agent gRPC server")
		ctx := context.Background()

		// Start the gRPC listener in a separate goroutine since Serve() blocks.
		serverErrCh := make(chan error, 1)
		go func() {
			if err := am.grpcServer.Start(ctx); err != nil {
				serverErrCh <- fmt.Errorf("agent gRPC server error: %w", err)
			}
		}()

		// Wait for the agent to connect and subscribe before allowing NIC
		// to proceed with configuration processing.
		nl.Infof(am.logger, "Waiting for nginx-agent to connect (timeout %v)...", agentConnectTimeout)
		select {
		case <-am.broadcaster.Ready():
			nl.Infof(am.logger, "nginx-agent connected and subscribed, proceeding with startup")
		case err := <-serverErrCh:
			done <- err
			return
		case <-time.After(agentConnectTimeout):
			done <- fmt.Errorf(
				"nginx-agent did not connect within %v — ensure the nginx-agent "+
					"sidecar container is running and can reach the gRPC server", agentConnectTimeout)
			return
		}
	}()
}

// Reload broadcasts a ConfigApplyRequest to the connected nginx-agent and
// blocks until the agent confirms. This preserves the synchronous contract
// that the Configurator expects.
//
// If the agent hasn't connected yet (startup race), Reload returns nil without
// sending — the config will be delivered via setInitialConfig when the agent
// subscribes. Start() handles the fatal timeout if the agent never connects.
func (am *AgentManager) Reload(isEndpointsUpdate bool) error {
	am.configVersion++
	am.UpdateConfigVersionFile()

	// If the agent hasn't subscribed yet, skip this reload. The current file
	// store contents will be sent via setInitialConfig when the agent connects.
	// Start() enforces the fatal timeout if it never connects.
	select {
	case <-am.broadcaster.Ready():
		// Agent is connected.
	default:
		nl.Infof(am.logger, "Agent not connected yet, deferring config apply to initial sync")
		return nil
	}

	fileOverviews, configVersion := am.fileStore.GetFileOverviews()

	nl.Infof(am.logger, "Reloading NGINX via agent, configVersion=%s, files=%d",
		configVersion, len(fileOverviews))

	start := time.Now()

	msg := broadcast.NginxAgentMessage{
		Type:          broadcast.ConfigApplyRequest,
		FileOverviews: fileOverviews,
		ConfigVersion: configVersion,
	}

	applied := am.broadcaster.Send(msg)
	duration := time.Since(start)

	if !applied {
		nl.Warnf(am.logger, "No agent subscribers connected, config not applied")
		am.metricsCollector.IncNginxReloadErrors()
		return fmt.Errorf("no agent subscribers connected to apply config")
	}

	am.metricsCollector.IncNginxReloadCount(isEndpointsUpdate)
	am.metricsCollector.UpdateLastReloadTime(duration)

	nl.Infof(am.logger, "NGINX reloaded via agent in %v", duration)

	return nil
}

// Quit stops the gRPC server. NGINX shutdown is handled by the nginx container.
func (am *AgentManager) Quit() {
	nl.Infof(am.logger, "Stopping agent gRPC server")
	am.grpcServer.Stop()
}

// Version returns a stub version. The actual nginx version is known to the
// nginx container; NIC discovers it post-connection.
func (am *AgentManager) Version() Version {
	return NewVersion("nginx version: nginx/0.0.0 (agent-mode)")
}

// UpdateConfigVersionFile generates the config-version.conf snippet and stores
// it in the file store. The main nginx.conf template includes this file, so it
// must exist for nginx to parse the config successfully.
func (am *AgentManager) UpdateConfigVersionFile() {
	cfg, err := am.verifyConfigGenerator.GenerateVersionConfig(am.configVersion)
	if err != nil {
		nl.Errorf(am.logger, "Error generating config version content: %v", err)
		return
	}
	am.fileStore.Set(agentConfigVersionFilename, cfg)
}

// SetPlusClients stores the NGINX Plus API client references.
func (am *AgentManager) SetPlusClients(plusClient *client.NginxClient, _ *http.Client) {
	am.plusClient = plusClient
}

// UpdateServersInPlus sends an NGINXPlusAction to update HTTP upstream servers
// via the agent.
func (am *AgentManager) UpdateServersInPlus(upstream string, servers []string, config ServerConfig) error {
	if !am.nginxPlus {
		return nil
	}

	upstreamServers := make([]*structpb.Struct, 0, len(servers))
	for _, s := range servers {
		fields := map[string]*structpb.Value{
			"server": structpb.NewStringValue(s),
		}
		if config.MaxFails != 0 {
			fields["max_fails"] = structpb.NewNumberValue(float64(config.MaxFails))
		}
		if config.MaxConns != 0 {
			fields["max_conns"] = structpb.NewNumberValue(float64(config.MaxConns))
		}
		if config.FailTimeout != "" {
			fields["fail_timeout"] = structpb.NewStringValue(config.FailTimeout)
		}
		if config.SlowStart != "" {
			fields["slow_start"] = structpb.NewStringValue(config.SlowStart)
		}
		upstreamServers = append(upstreamServers, &structpb.Struct{Fields: fields})
	}

	action := &pb.NGINXPlusAction{
		Action: &pb.NGINXPlusAction_UpdateHttpUpstreamServers{
			UpdateHttpUpstreamServers: &pb.UpdateHTTPUpstreamServers{
				HttpUpstreamName: upstream,
				Servers:          upstreamServers,
			},
		},
	}

	msg := broadcast.NginxAgentMessage{
		Type:            broadcast.APIRequest,
		NGINXPlusAction: action,
	}

	applied := am.broadcaster.Send(msg)
	if !applied {
		return fmt.Errorf("no agent subscribers connected to update upstream %s", upstream)
	}

	return nil
}

// UpdateStreamServersInPlus sends an NGINXPlusAction to update stream upstream
// servers via the agent.
func (am *AgentManager) UpdateStreamServersInPlus(upstream string, servers []string) error {
	if !am.nginxPlus {
		return nil
	}

	upstreamServers := make([]*structpb.Struct, 0, len(servers))
	for _, s := range servers {
		upstreamServers = append(upstreamServers, &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"server": structpb.NewStringValue(s),
			},
		})
	}

	action := &pb.NGINXPlusAction{
		Action: &pb.NGINXPlusAction_UpdateStreamServers{
			UpdateStreamServers: &pb.UpdateStreamServers{
				UpstreamStreamName: upstream,
				Servers:            upstreamServers,
			},
		},
	}

	msg := broadcast.NginxAgentMessage{
		Type:            broadcast.APIRequest,
		NGINXPlusAction: action,
	}

	applied := am.broadcaster.Send(msg)
	if !applied {
		return fmt.Errorf("no agent subscribers connected to update stream upstream %s", upstream)
	}

	return nil
}

// AppProtectPluginStart is a no-op in agent mode (deferred).
func (am *AgentManager) AppProtectPluginStart(_ chan error, _ string) {
	nl.Warnf(am.logger, "AppProtect plugin not supported in agent mode")
}

// AppProtectPluginQuit is a no-op in agent mode.
func (am *AgentManager) AppProtectPluginQuit() {}

// AppProtectDosAgentStart is a no-op in agent mode (deferred).
func (am *AgentManager) AppProtectDosAgentStart(_ chan error, _ bool, _ int, _ int, _ int) {
	nl.Warnf(am.logger, "AppProtect DoS agent not supported in agent mode")
}

// AppProtectDosAgentQuit is a no-op in agent mode.
func (am *AgentManager) AppProtectDosAgentQuit() {}

// AgentStart is a no-op -- the agent runs in the nginx container, not managed by NIC.
func (am *AgentManager) AgentStart(_ chan error, _ string) {}

// AgentQuit is a no-op -- the agent lifecycle is managed by the nginx container.
func (am *AgentManager) AgentQuit() {}

// AgentVersion returns a placeholder -- the real version is in the nginx container.
func (am *AgentManager) AgentVersion() string {
	return "v0.0.0-agent-mode"
}

// GetSecretsDir returns the secrets directory path used in the nginx container.
func (am *AgentManager) GetSecretsDir() string {
	return agentSecretsPath
}

// GetOSCABundlePath returns the default CA bundle path.
func (am *AgentManager) GetOSCABundlePath() (string, error) {
	return defaultCAPath, nil
}

// UpsertSplitClientsKeyVal updates a key-value pair via the NGINX Plus API.
// This goes directly through the Plus client since it's an API operation.
func (am *AgentManager) UpsertSplitClientsKeyVal(zoneName, key, _ string) {
	if am.plusClient == nil {
		return
	}
	nl.Debugf(am.logger, "Upserting key-val: zone=%s key=%s", zoneName, key)
	// This uses the Plus API directly -- key-val operations are not routed through the agent.
	// The Plus API socket would need to be shared or accessed via a different mechanism
	// in the two-container model. For now, this is a placeholder.
}

// DeleteKeyValStateFiles is a no-op in agent mode -- state files are in the
// nginx container.
func (am *AgentManager) DeleteKeyValStateFiles(_ string) {}

// Ensure AgentManager implements Manager at compile time.
var _ Manager = &AgentManager{}
