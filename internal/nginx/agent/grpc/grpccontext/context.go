// Package grpccontext provides gRPC context utilities for storing and retrieving
// agent connection identity information.
package grpccontext

import "context"

// GrpcInfo stores identity information for a gRPC client connection.
type GrpcInfo struct {
	// UUID is the unique identifier for the gRPC client (nginx-agent instance).
	UUID string
}

type contextGRPCKey struct{}

// NewGrpcContext returns a new context.Context with the provided GrpcInfo attached.
func NewGrpcContext(ctx context.Context, info GrpcInfo) context.Context {
	return context.WithValue(ctx, contextGRPCKey{}, info)
}

// FromContext returns the GrpcInfo saved in ctx if it exists.
// Returns false if there's no GrpcInfo in the context.
func FromContext(ctx context.Context) (GrpcInfo, bool) {
	v, ok := ctx.Value(contextGRPCKey{}).(GrpcInfo)
	return v, ok
}
