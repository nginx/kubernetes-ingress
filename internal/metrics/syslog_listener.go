package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/metrics/collectors"
)

// SyslogListener is an interface for syslog metrics listener
// that reads syslog metrics logged by nginx
type SyslogListener interface {
	Run()
	Stop()
}

// LatencyMetricsListener implements the SyslogListener interface
type LatencyMetricsListener struct {
	conn      *net.UnixConn
	addr      string
	collector collectors.LatencyCollector
	logger    *slog.Logger
}

// NewLatencyMetricsListener returns a LatencyMetricsListener that listens over a unix socket
// for syslog messages from nginx.
func NewLatencyMetricsListener(ctx context.Context, sockPath string, c collectors.LatencyCollector) SyslogListener {
	l := nl.LoggerFromContext(ctx)
	nl.Infof(l, "Starting latency metrics server listening on: %s", sockPath)
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{
		Name: sockPath,
		Net:  "unixgram",
	})
	if err != nil {
		nl.Errorf(l, "Failed to create latency metrics listener: %v. Latency metrics will not be collected.", err)
		return NewSyslogFakeServer()
	}
	return &LatencyMetricsListener{conn: conn, addr: sockPath, collector: c, logger: l}
}

// Run reads from the unix connection until an unrecoverable error occurs or the connection is closed.
func (l LatencyMetricsListener) Run() {
	buffer := make([]byte, 1024)
	for {
		n, err := l.conn.Read(buffer)
		if err != nil {
			if !isErrorRecoverable(err) {
				nl.Info(l.logger, "Stopping latency metrics listener")
				return
			}
		}
		go l.collector.RecordLatency(string(buffer[:n]))
	}
}

// Stop closes the unix connection of the listener.
func (l LatencyMetricsListener) Stop() {
	err := l.conn.Close()
	if err != nil {
		nl.Errorf(l.logger, "error closing latency metrics unix connection: %v", err)
	}
}

func isErrorRecoverable(err error) bool {
	var nerr *net.OpError
	return errors.As(err, &nerr) && nerr.Temporary()
}

// SyslogFakeListener is a fake implementation of the SyslogListener interface
type SyslogFakeListener struct{}

// NewSyslogFakeServer returns a SyslogFakeListener
func NewSyslogFakeServer() *SyslogFakeListener {
	return &SyslogFakeListener{}
}

// Run is a fake implementation of SyslogListener Run
func (s SyslogFakeListener) Run() {}

// Stop is a fake implementation of SyslogListener Stop
func (s SyslogFakeListener) Stop() {}
