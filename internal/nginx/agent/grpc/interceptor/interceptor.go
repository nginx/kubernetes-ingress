// Package interceptor provides gRPC server interceptors for the agent MPI server.
//
// The interceptor extracts the agent UUID from gRPC metadata headers when present
// (sent by the modified agent with InsecurePerRPCCredentials or the standard agent
// with Auth configured). When the UUID is NOT in metadata (unmodified agent without
// Auth), the interceptor lets the call through — the service handlers extract the
// agent identity from the request body (CreateConnectionRequest.Resource) instead.
package interceptor

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/nginx/kubernetes-ingress/internal/nginx/agent/grpc/grpccontext"
)

const headerUUID = "uuid"

// streamHandler wraps a grpc.ServerStream to replace the context.
type streamHandler struct {
	grpc.ServerStream
	ctx context.Context
}

func (sh *streamHandler) Context() context.Context {
	return sh.ctx
}

// ContextSetter is an interceptor that extracts the agent UUID from gRPC
// metadata and injects it into the context as GrpcInfo. If the UUID is not
// present in metadata, the call proceeds without GrpcInfo — the service
// handler is responsible for extracting identity from the request body.
type ContextSetter struct{}

// NewContextSetter returns a new ContextSetter interceptor.
func NewContextSetter() *ContextSetter {
	return &ContextSetter{}
}

// Stream returns a gRPC stream server interceptor.
func (c *ContextSetter) Stream() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		_ *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := extractGrpcInfo(ss.Context())
		return handler(srv, &streamHandler{
			ServerStream: ss,
			ctx:          ctx,
		})
	}
}

// Unary returns a gRPC unary server interceptor.
func (c *ContextSetter) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		ctx = extractGrpcInfo(ctx)
		return handler(ctx, req)
	}
}

// extractGrpcInfo reads the agent UUID from gRPC metadata and attaches
// it to the context. If the UUID is not present, the original context
// is returned unchanged.
func extractGrpcInfo(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	id := md.Get(headerUUID)
	if len(id) == 0 {
		return ctx
	}

	info := grpccontext.GrpcInfo{
		UUID: id[0],
	}

	return grpccontext.NewGrpcContext(ctx, info)
}
