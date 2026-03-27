package grpc

import "sync"

// ConnectionsTracker defines an interface to track connections between the
// control plane and nginx agents.
type ConnectionsTracker interface {
	Track(key string, conn Connection)
	GetConnection(key string) Connection
	SetInstanceID(key, id string)
	RemoveConnection(key string)
	// FirstConnectionID returns the key of the first tracked connection, or ""
	// if none. Used as a fallback when the agent UUID is not in gRPC metadata
	// (unmodified agent without Auth configured).
	FirstConnectionID() string
}

// Connection contains data about a single nginx agent connection.
type Connection struct {
	// InstanceID is the nginx instance ID reported by the agent.
	InstanceID string
	// PodName is the hostname of the pod running the agent.
	PodName string
}

// Ready returns true if the agent has registered itself and an nginx instance
// with the control plane (i.e. InstanceID has been set).
func (c *Connection) Ready() bool {
	return c.InstanceID != ""
}

// AgentConnectionsTracker keeps track of all connections between the control
// plane and nginx agents.
type AgentConnectionsTracker struct {
	connections map[string]Connection
	lock        sync.RWMutex
}

// NewConnectionsTracker returns a new AgentConnectionsTracker instance.
func NewConnectionsTracker() ConnectionsTracker {
	return &AgentConnectionsTracker{
		connections: make(map[string]Connection),
	}
}

// Track adds a connection to the tracking map.
func (c *AgentConnectionsTracker) Track(key string, conn Connection) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.connections[key] = conn
}

// GetConnection returns the requested connection.
func (c *AgentConnectionsTracker) GetConnection(key string) Connection {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.connections[key]
}

// SetInstanceID sets the nginx instanceID for a connection.
func (c *AgentConnectionsTracker) SetInstanceID(key, id string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if conn, ok := c.connections[key]; ok {
		conn.InstanceID = id
		c.connections[key] = conn
	}
}

// RemoveConnection removes a connection from the tracking map.
func (c *AgentConnectionsTracker) RemoveConnection(key string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	delete(c.connections, key)
}

// FirstConnectionID returns the key of the first tracked connection.
// In NIC's agent-mode there is typically only one agent, so this is a
// reliable fallback when the UUID isn't in gRPC metadata.
func (c *AgentConnectionsTracker) FirstConnectionID() string {
	c.lock.RLock()
	defer c.lock.RUnlock()

	for key := range c.connections {
		return key
	}
	return ""
}
