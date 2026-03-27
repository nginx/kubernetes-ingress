// Package agent implements the MPI (Management Plane Interface) gRPC server
// that nginx-agent connects to. It provides the CommandService and FileService
// endpoints, an in-memory FileStore for configuration, and a Broadcaster for
// pushing config updates to connected agents.
package agent

import (
	"log/slog"

	"google.golang.org/grpc"

	"github.com/nginx/kubernetes-ingress/internal/nginx/agent/broadcast"
	agentgrpc "github.com/nginx/kubernetes-ingress/internal/nginx/agent/grpc"
)

// CommandService is the exported handle for the MPI CommandService gRPC server.
type CommandService struct {
	svc *commandService
}

// NewCommandService creates a new CommandService.
func NewCommandService(
	logger *slog.Logger,
	store *FileStore,
	connTracker agentgrpc.ConnectionsTracker,
	broadcaster broadcast.Broadcaster,
) *CommandService {
	return &CommandService{
		svc: newCommandService(logger, store, connTracker, broadcaster),
	}
}

// Register registers the CommandService on the gRPC server.
func (c *CommandService) Register(server *grpc.Server) {
	c.svc.Register(server)
}

// FileService is the exported handle for the MPI FileService gRPC server.
type FileService struct {
	svc *fileService
}

// NewFileService creates a new FileService.
func NewFileService(
	logger *slog.Logger,
	store *FileStore,
	connTracker agentgrpc.ConnectionsTracker,
) *FileService {
	return &FileService{
		svc: newFileService(logger, store, connTracker),
	}
}

// Register registers the FileService on the gRPC server.
func (f *FileService) Register(server *grpc.Server) {
	f.svc.Register(server)
}

// RegisterServices returns a slice of gRPC service registration functions
// for the CommandService and FileService.
func RegisterServices(cmd *CommandService, file *FileService) []func(*grpc.Server) {
	return []func(*grpc.Server){
		cmd.Register,
		file.Register,
	}
}
