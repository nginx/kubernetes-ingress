// Package messenger provides a wrapper around the bidirectional Subscribe
// gRPC stream between the MPI command server and the nginx-agent.
package messenger

import (
	"context"
	"errors"

	pb "github.com/nginx/agent/v3/api/grpc/mpi/v1"
)

// Messenger is a wrapper around a gRPC bidirectional stream with the nginx agent.
type Messenger interface {
	Run(context.Context)
	Send(context.Context, *pb.ManagementPlaneRequest) error
	Messages() <-chan *pb.DataPlaneResponse
	Errors() <-chan error
}

// NginxAgentMessenger implements the Messenger interface.
type NginxAgentMessenger struct {
	incoming chan *pb.ManagementPlaneRequest
	outgoing chan *pb.DataPlaneResponse
	errorCh  chan error
	server   pb.CommandService_SubscribeServer
}

// New returns a new Messenger wrapping the given Subscribe stream.
func New(server pb.CommandService_SubscribeServer) Messenger {
	return &NginxAgentMessenger{
		incoming: make(chan *pb.ManagementPlaneRequest),
		outgoing: make(chan *pb.DataPlaneResponse),
		errorCh:  make(chan error),
		server:   server,
	}
}

// Run starts the Messenger to listen for any Send() or Recv() events over the stream.
func (m *NginxAgentMessenger) Run(ctx context.Context) {
	go m.handleRecv(ctx)
	m.handleSend(ctx)
}

// Send a message to the agent. Returns error if the context is canceled.
func (m *NginxAgentMessenger) Send(ctx context.Context, msg *pb.ManagementPlaneRequest) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.incoming <- msg:
	}
	return nil
}

func (m *NginxAgentMessenger) handleSend(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-m.incoming:
			err := m.server.Send(msg)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
					return
				}
				m.errorCh <- err
				return
			}
		}
	}
}

// Messages returns the data plane response channel.
func (m *NginxAgentMessenger) Messages() <-chan *pb.DataPlaneResponse {
	return m.outgoing
}

// Errors returns the error channel.
func (m *NginxAgentMessenger) Errors() <-chan error {
	return m.errorCh
}

// handleRecv handles incoming messages from the nginx agent.
// It blocks until Recv returns.
func (m *NginxAgentMessenger) handleRecv(ctx context.Context) {
	for {
		msg, err := m.server.Recv()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case m.errorCh <- err:
			}
			return
		}

		if msg == nil {
			close(m.outgoing)
			return
		}

		select {
		case <-ctx.Done():
			return
		case m.outgoing <- msg:
		}
	}
}
