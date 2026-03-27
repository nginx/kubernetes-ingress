// Package grpc provides the MPI gRPC server that nginx-agent connects to.
//
// Two transport modes are supported, selected at startup:
//
//   - Unix socket (default with --agent-mode): NIC listens on a Unix socket
//     shared with the nginx+agent container via an emptyDir volume. Requires
//     the Unix socket change in the agent (feature/unix-socket-support).
//
//   - TCP+TLS (with --agent-tls): NIC listens on localhost:8443 with a
//     self-signed TLS certificate. Works with the unmodified agent using its
//     existing host/port/TLS configuration. The CA cert is written to the
//     shared volume so the agent container can trust it.
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/nginx/agent/grpc/interceptor"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const (
	// SocketPath is the Unix socket path used for NIC ↔ nginx-agent communication
	// in Unix socket mode.
	SocketPath = "/var/run/nginx/agent.sock"

	keepAliveTime    = 15 * time.Second
	keepAliveTimeout = 10 * time.Second
)

// ErrStatusInvalidConnection is returned when a gRPC connection cannot be validated.
var ErrStatusInvalidConnection = fmt.Errorf("invalid connection")

// Server is a gRPC server for communicating with the nginx agent.
// It supports two transport modes: Unix socket (insecure, local) and
// TCP+TLS (encrypted, suitable for use with the unmodified agent).
type Server struct {
	logger           *slog.Logger
	registerServices []func(*grpc.Server)
	// socketPath is set for Unix socket mode.
	socketPath string
	// tlsConfig is set for TCP+TLS mode. Cert/key/CA are loaded from a
	// Kubernetes Secret mounted into the pod.
	tlsConfig *TLSConfig
	// tlsPort is the TCP port for TLS mode.
	tlsPort    int
	grpcServer *grpc.Server
}

// NewServer creates a new gRPC server using Unix socket transport.
func NewServer(
	logger *slog.Logger,
	socketPath string,
	registerSvcs []func(*grpc.Server),
) *Server {
	return &Server{
		logger:           logger,
		socketPath:       socketPath,
		registerServices: registerSvcs,
	}
}

// NewTLSServer creates a new gRPC server using TCP+TLS transport.
// The cert, key, and CA are loaded from files on disk (typically from a
// Kubernetes Secret mounted into the pod as a volume).
func NewTLSServer(
	logger *slog.Logger,
	port int,
	tlsConfig *TLSConfig,
	registerSvcs []func(*grpc.Server),
) *Server {
	return &Server{
		logger:           logger,
		tlsConfig:        tlsConfig,
		tlsPort:          port,
		registerServices: registerSvcs,
	}
}

// IsTLS returns true if the server is configured for TCP+TLS mode.
func (s *Server) IsTLS() bool {
	return s.tlsConfig != nil
}

// Start starts the gRPC server. It blocks until the server stops or the
// context is canceled.
func (s *Server) Start(ctx context.Context) error {
	if s.IsTLS() {
		return s.startTLS(ctx)
	}
	return s.startUnixSocket(ctx)
}

// startUnixSocket starts the gRPC server listening on a Unix socket.
func (s *Server) startUnixSocket(ctx context.Context) error {
	// Clean up stale socket file from a previous run.
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove stale socket %s: %w", s.socketPath, err)
	}

	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", s.socketPath, err)
	}

	// Make the socket readable/writable by the nginx-agent container (which may
	// run as a different UID in the same pod).
	if err := os.Chmod(s.socketPath, 0o660); err != nil { //nolint:gosec // G302: socket must be writable by both containers in the pod
		nl.Warnf(s.logger, "Failed to chmod socket %s: %v", s.socketPath, err)
	}

	s.grpcServer = s.buildGRPCServer()

	go s.waitForShutdown(ctx)

	nl.Infof(s.logger, "Agent gRPC server listening on unix://%s", s.socketPath)

	return s.grpcServer.Serve(listener)
}

// startTLS starts the gRPC server listening on a TCP port with TLS.
// TLS is handled by grpc.Creds() (not by wrapping the listener) so that
// gRPC properly advertises the "h2" ALPN protocol during the TLS handshake.
// The cert/key are loaded from a Kubernetes Secret mounted on disk.
func (s *Server) startTLS(ctx context.Context) error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.tlsPort)
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.grpcServer, err = s.buildGRPCServerWithTLS()
	if err != nil {
		return err
	}

	go s.waitForShutdown(ctx)

	nl.Infof(s.logger, "Agent gRPC server listening on %s (TLS), cert=%s, ca=%s",
		addr, s.tlsConfig.CertPath, s.tlsConfig.CAPath)

	return s.grpcServer.Serve(listener)
}

// buildGRPCServer builds the gRPC server with the common interceptors and
// keepalive settings (insecure transport for Unix socket).
func (s *Server) buildGRPCServer() *grpc.Server {
	ctxInterceptor := interceptor.NewContextSetter()

	srv := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    keepAliveTime,
			Timeout: keepAliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             keepAliveTime,
			PermitWithoutStream: true,
		}),
		grpc.ChainStreamInterceptor(ctxInterceptor.Stream()),
		grpc.ChainUnaryInterceptor(ctxInterceptor.Unary()),
	)

	for _, register := range s.registerServices {
		register(srv)
	}

	return srv
}

// buildGRPCServerWithTLS builds the gRPC server with TLS transport credentials
// loaded from the mounted Secret files.
func (s *Server) buildGRPCServerWithTLS() (*grpc.Server, error) {
	serverCert, err := LoadTLSCert(s.tlsConfig.CertPath, s.tlsConfig.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server TLS certificate: %w", err)
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	})

	ctxInterceptor := interceptor.NewContextSetter()

	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    keepAliveTime,
			Timeout: keepAliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             keepAliveTime,
			PermitWithoutStream: true,
		}),
		grpc.ChainStreamInterceptor(ctxInterceptor.Stream()),
		grpc.ChainUnaryInterceptor(ctxInterceptor.Unary()),
	)

	for _, register := range s.registerServices {
		register(srv)
	}

	return srv, nil
}

func (s *Server) waitForShutdown(ctx context.Context) {
	<-ctx.Done()
	nl.Infof(s.logger, "Shutting down agent gRPC server")
	// Use Stop() instead of GracefulStop() because the Subscribe stream is
	// long-lived and would prevent graceful shutdown from completing quickly.
	s.grpcServer.Stop()
}

// Stop stops the gRPC server immediately.
func (s *Server) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.Stop()
	}
}
