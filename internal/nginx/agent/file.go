package agent

import (
	"bytes"
	"context"
	"log/slog"
	"math"

	pb "github.com/nginx/agent/v3/api/grpc/mpi/v1"
	"github.com/nginx/agent/v3/pkg/files"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	agentgrpc "github.com/nginx/kubernetes-ingress/internal/nginx/agent/grpc"
)

const defaultChunkSize uint32 = 2097152 // 2MB

// fileService handles file management between the control plane and the agent.
type fileService struct {
	pb.FileServiceServer
	fileStore   *FileStore
	connTracker agentgrpc.ConnectionsTracker
	logger      *slog.Logger
}

func newFileService(
	logger *slog.Logger,
	store *FileStore,
	connTracker agentgrpc.ConnectionsTracker,
) *fileService {
	return &fileService{
		logger:      logger,
		fileStore:   store,
		connTracker: connTracker,
	}
}

// Register registers the FileService on the given gRPC server.
func (fs *fileService) Register(server *grpc.Server) {
	pb.RegisterFileServiceServer(server, fs)
}

// GetFile is called by the agent when it needs to download a file for a ConfigApplyRequest.
func (fs *fileService) GetFile(
	_ context.Context,
	req *pb.GetFileRequest,
) (*pb.GetFileResponse, error) {
	if req.GetFileMeta() == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	contents, err := fs.getFileContents(req)
	if err != nil {
		return nil, err
	}

	return &pb.GetFileResponse{
		Contents: &pb.FileContents{
			Contents: contents,
		},
	}, nil
}

// GetFileStream is called by the agent when it needs to download a file in chunks.
func (fs *fileService) GetFileStream(
	req *pb.GetFileRequest,
	server grpc.ServerStreamingServer[pb.FileDataChunk],
) error {
	if req.GetFileMeta() == nil || req.GetMessageMeta() == nil {
		return status.Error(codes.InvalidArgument, "invalid request")
	}

	contents, err := fs.getFileContents(req)
	if err != nil {
		return err
	}

	size := req.GetFileMeta().GetSize()
	var sizeUint32 uint32
	if size > math.MaxUint32 {
		return status.Error(codes.Internal, "file size too large")
	}
	sizeUint32 = uint32(size) //nolint:gosec // validated above

	nl.Debugf(fs.logger, "Sending chunked file to agent: %s", req.GetFileMeta().GetName())

	if err := files.SendChunkedFile(
		req.GetMessageMeta(),
		pb.FileDataChunk_Header{
			Header: &pb.FileDataChunkHeader{
				ChunkSize: defaultChunkSize,
				Chunks:    calculateChunks(sizeUint32, defaultChunkSize),
				FileMeta: &pb.FileMeta{
					Name:        req.GetFileMeta().GetName(),
					Hash:        req.GetFileMeta().GetHash(),
					Permissions: req.GetFileMeta().GetPermissions(),
					Size:        size,
				},
			},
		},
		bytes.NewReader(contents),
		server,
	); err != nil {
		return status.Error(codes.Aborted, err.Error())
	}

	return nil
}

func (fs *fileService) getFileContents(req *pb.GetFileRequest) ([]byte, error) {
	filename := req.GetFileMeta().GetName()
	hash := req.GetFileMeta().GetHash()

	contents, foundHash := fs.fileStore.GetFile(filename, hash)
	if len(contents) == 0 {
		if foundHash != "" {
			nl.Debugf(fs.logger, "File %s found with wrong hash: wanted=%s found=%s",
				filename, hash, foundHash)
		}
		return nil, status.Errorf(codes.NotFound, "file not found: %s", filename)
	}

	nl.Debugf(fs.logger, "Getting file for agent: %s hash=%s", filename, foundHash)

	return contents, nil
}

func calculateChunks(fileSize, chunkSize uint32) uint32 {
	remainder, divide := fileSize%chunkSize, fileSize/chunkSize
	if remainder > 0 {
		return divide + 1
	}
	return divide
}

// GetOverview is not used in NIC's model -- return empty.
func (*fileService) GetOverview(context.Context, *pb.GetOverviewRequest) (*pb.GetOverviewResponse, error) {
	return &pb.GetOverviewResponse{}, nil
}

// UpdateOverview is called by the agent on startup and whenever files change.
// NIC is authoritative for config, so we return an empty response.
func (*fileService) UpdateOverview(context.Context, *pb.UpdateOverviewRequest) (*pb.UpdateOverviewResponse, error) {
	return &pb.UpdateOverviewResponse{}, nil
}

// UpdateFile is a no-op -- NIC is the authoritative config source.
func (*fileService) UpdateFile(context.Context, *pb.UpdateFileRequest) (*pb.UpdateFileResponse, error) {
	return &pb.UpdateFileResponse{}, nil
}

// UpdateFileStream is a no-op -- NIC is the authoritative config source.
func (*fileService) UpdateFileStream(grpc.ClientStreamingServer[pb.FileDataChunk, pb.UpdateFileResponse]) error {
	return nil
}
