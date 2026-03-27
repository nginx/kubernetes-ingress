// Package broadcast provides a fan-out mechanism for sending NGINX configuration
// updates to all connected nginx-agent subscribers.
package broadcast

import (
	"context"
	"sync"

	"github.com/google/uuid"
	pb "github.com/nginx/agent/v3/api/grpc/mpi/v1"
)

// Broadcaster defines an interface for consumers to subscribe to config updates.
type Broadcaster interface {
	Subscribe() SubscriberChannels
	Send(NginxAgentMessage) bool
	CancelSubscription(string)
	// Ready returns a channel that is closed when at least one subscriber is connected.
	Ready() <-chan struct{}
}

// SubscriberChannels are the channels sent to the subscriber to listen and respond on.
type SubscriberChannels struct {
	ListenCh   <-chan NginxAgentMessage
	ResponseCh chan<- struct{}
	ID         string
}

// storedChannels are the reverse-direction channels stored by the broadcaster.
type storedChannels struct {
	listenCh   chan<- NginxAgentMessage
	responseCh <-chan struct{}
	id         string
}

// NginxBroadcaster sends out a signal when NGINX configuration has been updated.
// The signal is received by any agent subscription. The agent subscription will
// then send a response of whether the configuration was successfully applied.
type NginxBroadcaster struct {
	publishCh chan NginxAgentMessage
	subCh     chan storedChannels
	unsubCh   chan string
	listeners map[string]storedChannels
	doneCh    chan struct{}
	readyCh   chan struct{}
}

// NewNginxBroadcaster returns a new NginxBroadcaster instance.
func NewNginxBroadcaster(ctx context.Context) *NginxBroadcaster {
	broadcaster := &NginxBroadcaster{
		listeners: make(map[string]storedChannels),
		publishCh: make(chan NginxAgentMessage),
		subCh:     make(chan storedChannels),
		unsubCh:   make(chan string),
		doneCh:    make(chan struct{}),
		readyCh:   make(chan struct{}),
	}
	go broadcaster.run(ctx)

	return broadcaster
}

// Subscribe allows a listener to subscribe to broadcast messages.
func (b *NginxBroadcaster) Subscribe() SubscriberChannels {
	listenCh := make(chan NginxAgentMessage)
	responseCh := make(chan struct{})
	id := uuid.NewString()

	subscriberChans := SubscriberChannels{
		ID:         id,
		ListenCh:   listenCh,
		ResponseCh: responseCh,
	}
	stored := storedChannels{
		id:         id,
		listenCh:   listenCh,
		responseCh: responseCh,
	}

	b.subCh <- stored
	return subscriberChans
}

// Send the message to all listeners. Wait for all listeners to respond.
// Returns true if there were listeners that received the message.
func (b *NginxBroadcaster) Send(message NginxAgentMessage) bool {
	b.publishCh <- message
	<-b.doneCh

	return len(b.listeners) > 0
}

// CancelSubscription removes a subscriber from the channel list.
func (b *NginxBroadcaster) CancelSubscription(id string) {
	b.unsubCh <- id
}

// Ready returns a channel that is closed when at least one subscriber is connected.
func (b *NginxBroadcaster) Ready() <-chan struct{} {
	return b.readyCh
}

// run starts the broadcaster loop.
func (b *NginxBroadcaster) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case channels := <-b.subCh:
			b.listeners[channels.id] = channels
			if len(b.listeners) == 1 {
				select {
				case <-b.readyCh:
					// already closed
				default:
					close(b.readyCh)
				}
			}
		case id := <-b.unsubCh:
			delete(b.listeners, id)
		case msg := <-b.publishCh:
			var wg sync.WaitGroup

			for _, channels := range b.listeners {
				wg.Add(1)
				go func(ch storedChannels) {
					defer wg.Done()
					ch.listenCh <- msg
					<-ch.responseCh
				}(channels)
			}
			wg.Wait()

			b.doneCh <- struct{}{}
		}
	}
}

// MessageType is the type of message to be sent.
type MessageType int

const (
	// ConfigApplyRequest sends files to update nginx configuration.
	ConfigApplyRequest MessageType = iota
	// APIRequest sends an NGINX Plus API request to update configuration.
	APIRequest
)

// NginxAgentMessage is sent to all subscribers for either a ConfigApplyRequest
// or an APIActionRequest.
type NginxAgentMessage struct {
	// ConfigVersion is the hashed configuration version of the included files.
	ConfigVersion string
	// NGINXPlusAction is an NGINX Plus API action to be sent.
	NGINXPlusAction *pb.NGINXPlusAction
	// FileOverviews contain the overviews of all files to be sent.
	FileOverviews []*pb.File
	// Type defines the type of message to be sent.
	Type MessageType
}
