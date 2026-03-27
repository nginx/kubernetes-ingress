package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	pb "github.com/nginx/agent/v3/api/grpc/mpi/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/nginx/agent/broadcast"
	agentgrpc "github.com/nginx/kubernetes-ingress/internal/nginx/agent/grpc"
	"github.com/nginx/kubernetes-ingress/internal/nginx/agent/grpc/grpccontext"
	"github.com/nginx/kubernetes-ingress/internal/nginx/agent/grpc/messenger"
)

const connectionWaitTimeout = 30 * time.Second

// commandService handles the connection and subscription to the data plane agent.
type commandService struct {
	pb.CommandServiceServer
	fileStore         *FileStore
	connTracker       agentgrpc.ConnectionsTracker
	broadcaster       broadcast.Broadcaster
	logger            *slog.Logger
	connectionTimeout time.Duration
}

func newCommandService(
	logger *slog.Logger,
	store *FileStore,
	connTracker agentgrpc.ConnectionsTracker,
	broadcaster broadcast.Broadcaster,
) *commandService {
	return &commandService{
		connectionTimeout: connectionWaitTimeout,
		logger:            logger,
		connTracker:       connTracker,
		fileStore:         store,
		broadcaster:       broadcaster,
	}
}

// Register registers the CommandService on the given gRPC server.
func (cs *commandService) Register(server *grpc.Server) {
	pb.RegisterCommandServiceServer(server, cs)
}

// CreateConnection registers a data plane agent with the control plane.
func (cs *commandService) CreateConnection(
	ctx context.Context,
	req *pb.CreateConnectionRequest,
) (*pb.CreateConnectionResponse, error) {
	if req == nil {
		return nil, errors.New("empty connection request")
	}

	resource := req.GetResource()
	podName := resource.GetContainerInfo().GetHostname()
	nl.Infof(cs.logger, "Creating connection for nginx pod: %s", podName)

	// Use UUID from gRPC metadata if available (modified agent with
	// InsecurePerRPCCredentials or agent with Auth configured).
	// Otherwise, extract the agent UUID from the resource instances.
	agentUUID := ""
	if grpcInfo, ok := grpccontext.FromContext(ctx); ok {
		agentUUID = grpcInfo.UUID
	}
	if agentUUID == "" {
		agentUUID = getAgentInstanceID(resource.GetInstances())
	}
	if agentUUID == "" {
		return nil, grpcStatus.Error(codes.InvalidArgument, "unable to determine agent identity")
	}

	instanceID := getNginxInstanceID(resource.GetInstances())

	conn := agentgrpc.Connection{
		PodName:    podName,
		InstanceID: instanceID,
	}
	cs.connTracker.Track(agentUUID, conn)

	return &pb.CreateConnectionResponse{
		Response: &pb.CommandResponse{
			Status: pb.CommandResponse_COMMAND_STATUS_OK,
		},
	}, nil
}

// Subscribe is the bidirectional streaming RPC for agent ↔ control plane communication.
//
//nolint:gocyclo // matching NGF's pattern; complexity is inherent to the event loop
func (cs *commandService) Subscribe(in pb.CommandService_SubscribeServer) error {
	ctx := in.Context()

	// Try UUID from metadata first, then fall back to first tracked connection.
	// The unmodified agent doesn't send UUID in metadata for streaming RPCs.
	grpcInfo, ok := grpccontext.FromContext(ctx)
	if !ok {
		uuid := cs.connTracker.FirstConnectionID()
		if uuid == "" {
			return grpcStatus.Error(codes.FailedPrecondition, "no tracked connections, call CreateConnection first")
		}
		grpcInfo = grpccontext.GrpcInfo{UUID: uuid}
	}
	defer cs.connTracker.RemoveConnection(grpcInfo.UUID)

	// Wait for the agent to report its nginx instanceID
	conn, err := cs.waitForConnection(ctx, grpcInfo)
	if err != nil {
		nl.Errorf(cs.logger, "Error waiting for agent connection: %v", err)
		return err
	}

	nl.Infof(cs.logger, "Successfully connected to nginx agent, uuid=%s, pod=%s", grpcInfo.UUID, conn.PodName)

	msgr := messenger.New(in)
	go msgr.Run(ctx)

	// Apply current config before starting event loop
	if err := cs.setInitialConfig(ctx, conn, msgr); err != nil {
		return err
	}

	// Subscribe to the broadcaster for updates
	channels := cs.broadcaster.Subscribe()
	defer cs.broadcaster.CancelSubscription(channels.ID)

	for {
		select {
		case <-ctx.Done():
			select {
			case channels.ResponseCh <- struct{}{}:
			default:
			}
			return grpcStatus.Error(codes.Canceled, context.Cause(ctx).Error())
		case msg := <-channels.ListenCh:
			var req *pb.ManagementPlaneRequest
			switch msg.Type {
			case broadcast.ConfigApplyRequest:
				req = buildConfigApplyRequest(msg.FileOverviews, conn.InstanceID, msg.ConfigVersion)
			case broadcast.APIRequest:
				req = buildPlusAPIRequest(msg.NGINXPlusAction, conn.InstanceID)
			default:
				nl.Errorf(cs.logger, "Unknown request type %d", msg.Type)
				channels.ResponseCh <- struct{}{}
				continue
			}

			if err := msgr.Send(ctx, req); err != nil {
				nl.Errorf(cs.logger, "Error sending request to agent: %v", err)
				channels.ResponseCh <- struct{}{}
				return grpcStatus.Error(codes.Internal, err.Error())
			}

			// Wait for agent response or error
			select {
			case <-ctx.Done():
				channels.ResponseCh <- struct{}{}
				return grpcStatus.Error(codes.Canceled, context.Cause(ctx).Error())
			case err := <-msgr.Errors():
				nl.Errorf(cs.logger, "Connection error: %v", err)
				channels.ResponseCh <- struct{}{}
				if errors.Is(err, io.EOF) {
					return grpcStatus.Error(codes.Aborted, err.Error())
				}
				return grpcStatus.Error(codes.Internal, err.Error())
			case resp := <-msgr.Messages():
				res := resp.GetCommandResponse()
				if res.GetStatus() != pb.CommandResponse_COMMAND_STATUS_OK {
					if !isRollbackMessage(res.GetMessage()) {
						nl.Errorf(cs.logger, "Agent config apply error: msg=%s error=%s",
							res.GetMessage(), res.GetError())
					}
				}
				channels.ResponseCh <- struct{}{}
			}

		case err := <-msgr.Errors():
			nl.Errorf(cs.logger, "Connection error from agent: %v", err)
			select {
			case channels.ResponseCh <- struct{}{}:
			default:
			}
			if errors.Is(err, io.EOF) {
				return grpcStatus.Error(codes.Aborted, err.Error())
			}
			return grpcStatus.Error(codes.Internal, err.Error())

		case resp := <-msgr.Messages():
			// Unsolicited response (e.g. from initial config or rollback)
			res := resp.GetCommandResponse()
			if res.GetStatus() != pb.CommandResponse_COMMAND_STATUS_OK {
				if !isRollbackMessage(res.GetMessage()) {
					nl.Warnf(cs.logger, "Unsolicited agent response: msg=%s error=%s",
						res.GetMessage(), res.GetError())
				}
			}
		}
	}
}

func (cs *commandService) waitForConnection(
	ctx context.Context,
	grpcInfo grpccontext.GrpcInfo,
) (*agentgrpc.Connection, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	timer := time.NewTimer(cs.connectionTimeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, errors.New("timed out waiting for agent to register nginx instance")
		case <-ticker.C:
			if conn := cs.connTracker.GetConnection(grpcInfo.UUID); conn.Ready() {
				return &conn, nil
			}
		}
	}
}

// setInitialConfig sends the current file overview to the agent on first connect.
func (cs *commandService) setInitialConfig(
	ctx context.Context,
	conn *agentgrpc.Connection,
	msgr messenger.Messenger,
) error {
	fileOverviews, configVersion := cs.fileStore.GetFileOverviews()

	nl.Infof(cs.logger, "Sending initial configuration to agent, configVersion=%s", configVersion)

	req := buildConfigApplyRequest(fileOverviews, conn.InstanceID, configVersion)
	if err := msgr.Send(ctx, req); err != nil {
		return grpcStatus.Error(codes.Internal, err.Error())
	}

	// Wait for the agent to confirm the initial config
	for {
		select {
		case <-ctx.Done():
			return grpcStatus.Error(codes.Canceled, context.Cause(ctx).Error())
		case err := <-msgr.Errors():
			if errors.Is(err, io.EOF) {
				return grpcStatus.Error(codes.Aborted, err.Error())
			}
			return grpcStatus.Error(codes.Internal, err.Error())
		case resp := <-msgr.Messages():
			res := resp.GetCommandResponse()
			if res.GetStatus() != pb.CommandResponse_COMMAND_STATUS_OK {
				if isRollbackMessage(res.GetMessage()) {
					continue
				}
				nl.Warnf(cs.logger, "Initial config apply error: msg=%s error=%s",
					res.GetMessage(), res.GetError())
			} else {
				nl.Infof(cs.logger, "Initial configuration applied successfully")
			}
			return nil
		}
	}
}

// UpdateDataPlaneStatus is called by the agent to report nginx instance discovery.
func (cs *commandService) UpdateDataPlaneStatus(
	ctx context.Context,
	req *pb.UpdateDataPlaneStatusRequest,
) (*pb.UpdateDataPlaneStatusResponse, error) {
	if req == nil {
		return nil, errors.New("empty UpdateDataPlaneStatus request")
	}

	grpcInfo, ok := grpccontext.FromContext(ctx)
	if !ok {
		uuid := cs.connTracker.FirstConnectionID()
		if uuid == "" {
			return nil, grpcStatus.Error(codes.FailedPrecondition, "no tracked connections")
		}
		grpcInfo = grpccontext.GrpcInfo{UUID: uuid}
	}

	instanceID := getNginxInstanceID(req.GetResource().GetInstances())
	if instanceID == "" {
		return nil, grpcStatus.Errorf(codes.InvalidArgument, "request does not contain nginx instanceID")
	}

	cs.connTracker.SetInstanceID(grpcInfo.UUID, instanceID)
	nl.Debugf(cs.logger, "Agent reported nginx instanceID=%s", instanceID)

	return &pb.UpdateDataPlaneStatusResponse{}, nil
}

// UpdateDataPlaneHealth is a health ping from the agent -- currently a no-op.
func (*commandService) UpdateDataPlaneHealth(
	context.Context,
	*pb.UpdateDataPlaneHealthRequest,
) (*pb.UpdateDataPlaneHealthResponse, error) {
	return &pb.UpdateDataPlaneHealthResponse{}, nil
}

func buildConfigApplyRequest(fileOverviews []*pb.File, instanceID, version string) *pb.ManagementPlaneRequest {
	return &pb.ManagementPlaneRequest{
		MessageMeta: &pb.MessageMeta{
			MessageId:     uuid.NewString(),
			CorrelationId: uuid.NewString(),
			Timestamp:     timestamppb.Now(),
		},
		Request: &pb.ManagementPlaneRequest_ConfigApplyRequest{
			ConfigApplyRequest: &pb.ConfigApplyRequest{
				Overview: &pb.FileOverview{
					Files: fileOverviews,
					ConfigVersion: &pb.ConfigVersion{
						InstanceId: instanceID,
						Version:    version,
					},
				},
			},
		},
	}
}

func buildPlusAPIRequest(action *pb.NGINXPlusAction, instanceID string) *pb.ManagementPlaneRequest {
	return &pb.ManagementPlaneRequest{
		MessageMeta: &pb.MessageMeta{
			MessageId:     uuid.NewString(),
			CorrelationId: uuid.NewString(),
			Timestamp:     timestamppb.Now(),
		},
		Request: &pb.ManagementPlaneRequest_ActionRequest{
			ActionRequest: &pb.APIActionRequest{
				InstanceId: instanceID,
				Action: &pb.APIActionRequest_NginxPlusAction{
					NginxPlusAction: action,
				},
			},
		},
	}
}

func getNginxInstanceID(instances []*pb.Instance) string {
	for _, instance := range instances {
		instanceType := instance.GetInstanceMeta().GetInstanceType()
		if instanceType == pb.InstanceMeta_INSTANCE_TYPE_NGINX ||
			instanceType == pb.InstanceMeta_INSTANCE_TYPE_NGINX_PLUS {
			return instance.GetInstanceMeta().GetInstanceId()
		}
	}
	return ""
}

func getAgentInstanceID(instances []*pb.Instance) string {
	for _, instance := range instances {
		if instance.GetInstanceMeta().GetInstanceType() == pb.InstanceMeta_INSTANCE_TYPE_AGENT {
			return instance.GetInstanceMeta().GetInstanceId()
		}
	}
	return ""
}

func isRollbackMessage(msg string) bool {
	msgToLower := strings.ToLower(msg)
	return strings.Contains(msgToLower, "rollback successful") ||
		strings.Contains(msgToLower, "rollback failed")
}
