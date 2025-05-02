package nginx

import (
	"testing"

	"github.com/nginx/nginx-plus-go-client/v2/client"
)

// Helper functions to create pointers
func ptrInt(i int) *int    { return &i }
func ptrBool(b bool) *bool { return &b }

func TestFormatUpdateServersInPlusLog(t *testing.T) {
	tests := []struct {
		name     string
		input    []client.UpstreamServer
		expected string
	}{
		{
			name:     "Empty input",
			input:    []client.UpstreamServer{},
			expected: "[]",
		},
		{
			name: "Single server with all fields set",
			input: []client.UpstreamServer{
				{
					MaxConns:    ptrInt(100),
					MaxFails:    ptrInt(3),
					Backup:      ptrBool(true),
					Down:        ptrBool(false),
					Weight:      ptrInt(10),
					Server:      "192.168.1.1:8080",
					FailTimeout: "30s",
					SlowStart:   "10s",
					Route:       "route1",
					Service:     "serviceA",
					ID:          0,
					Drain:       true,
				},
			},
			expected: "[{MaxConns:100 MaxFails:3 Backup:true Down:false Weight:10 Server:192.168.1.1:8080 FailTimeout:30s SlowStart:10s Route:route1 Service:serviceA ID:0 Drain:true}]",
		},
		{
			name: "Multiple servers",
			input: []client.UpstreamServer{
				{
					MaxConns:    ptrInt(50),
					MaxFails:    ptrInt(2),
					Backup:      ptrBool(false),
					Down:        ptrBool(true),
					Weight:      ptrInt(5),
					Server:      "192.168.1.2:8080",
					FailTimeout: "20s",
					SlowStart:   "5s",
					Route:       "route2",
					Service:     "serviceB",
					ID:          1,
					Drain:       false,
				},
				{
					MaxConns:    ptrInt(150),
					MaxFails:    ptrInt(5),
					Backup:      ptrBool(true),
					Down:        ptrBool(false),
					Weight:      ptrInt(15),
					Server:      "192.168.1.3:8080",
					FailTimeout: "40s",
					SlowStart:   "20s",
					Route:       "route3",
					Service:     "serviceC",
					ID:          2,
					Drain:       true,
				},
			},
			expected: "[{MaxConns:50 MaxFails:2 Backup:false Down:true Weight:5 Server:192.168.1.2:8080 FailTimeout:20s SlowStart:5s Route:route2 Service:serviceB ID:1 Drain:false} {MaxConns:150 MaxFails:5 Backup:true Down:false Weight:15 Server:192.168.1.3:8080 FailTimeout:40s SlowStart:20s Route:route3 Service:serviceC ID:2 Drain:true}]",
		},
		{
			name: "Servers with nil pointer fields",
			input: []client.UpstreamServer{
				{
					MaxConns:    nil, // Should default to 0
					MaxFails:    ptrInt(4),
					Backup:      nil, // Should default to false
					Down:        ptrBool(true),
					Weight:      nil, // Should default to 0
					Server:      "192.168.1.4:8080",
					FailTimeout: "",
					SlowStart:   "",
					Route:       "",
					Service:     "",
					ID:          0,
					Drain:       false,
				},
			},
			expected: "[{MaxConns:0 MaxFails:4 Backup:false Down:true Weight:0 Server:192.168.1.4:8080 FailTimeout: SlowStart: Route: Service: ID:0 Drain:false}]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := formatUpdateServersInPlusLog(tc.input)
			if actual != tc.expected {
				t.Errorf("FormatUpdateServersInPlusLog() = %v, want %v", actual, tc.expected)
			}
		})
	}
}
