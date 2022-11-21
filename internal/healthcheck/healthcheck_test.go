package healthcheck_test

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"math/rand"
	"net"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginxinc/kubernetes-ingress/internal/healthcheck"
	"github.com/nginxinc/nginx-plus-go-client/client"
)

// newTestHealthServer is a helper func responsible for creating,
// starting and shutting down healthcheck server for each test.
func newTestHealthServer(t *testing.T) *healthcheck.HealthServer {
	t.Helper()

	l, err := net.Listen("tcp", ":0") //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck

	addr := l.Addr().String()
	hs, err := healthcheck.NewHealthServer(addr, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := hs.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	t.Cleanup(func() {
		err := hs.Shutdown(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	})
	return hs
}

func TestHealthCheckServer_Returns404OnMissingHostname(t *testing.T) {
	t.Parallel()

	hs := newTestHealthServer(t)
	hs.UpstreamsForHost = getUpstreamsForHost
	hs.NginxUpstreams = getUpstreamsFromNGINXAllUp

	resp, err := http.Get(hs.URL + "probe/") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNotFound {
		t.Error(resp.StatusCode)
	}
}

//nolint:gosec
func generateStringOfLength(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func TestHealthCheckServer_Returns414OnTooLongHostname(t *testing.T) {
	t.Parallel()

	hs := newTestHealthServer(t)
	hs.UpstreamsForHost = getUpstreamsForHost
	hs.NginxUpstreams = getUpstreamsFromNGINXAllUp

	hostname := generateStringOfLength(256)
	resp, err := http.Get(hs.URL + "probe/" + hostname) //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusRequestURITooLong {
		t.Error(resp.StatusCode)
	}
}

func TestHealthCheckServer_ReturnsCorrectHTTPForValidHostnameLength(t *testing.T) {
	t.Parallel()

	hs := newTestHealthServer(t)
	hs.UpstreamsForHost = getUpstreamsForHost
	hs.NginxUpstreams = getUpstreamsFromNGINXAllUp

	hostname := generateStringOfLength(254)
	resp, err := http.Get(hs.URL + "probe/" + hostname) //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNotFound {
		t.Error(resp.StatusCode)
	}
}

func TestHealthCheckServer_ReturnsCorrectStatsForHostnameForAllPeersUp(t *testing.T) {
	t.Parallel()

	hs := newTestHealthServer(t)
	hs.UpstreamsForHost = getUpstreamsForHost
	hs.NginxUpstreams = getUpstreamsFromNGINXAllUp

	resp, err := http.Get(hs.URL + "probe/bar.tea.com") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}

	want := healthcheck.HostStats{
		Total:     3,
		Up:        3,
		Unhealthy: 0,
	}
	var got healthcheck.HostStats
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestHealthCheckServer_ReturnsCorrectStatsAndCorrectHTTPCodeForHostnameOnAllPeersDown(t *testing.T) {
	t.Parallel()

	hs := newTestHealthServer(t)
	hs.UpstreamsForHost = getUpstreamsForHost
	hs.NginxUpstreams = getUpstreamsFromNGINXAllUnhealthy

	resp, err := http.Get(hs.URL + "probe/bar.tea.com") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatal(resp.StatusCode)
	}

	want := healthcheck.HostStats{
		Total:     3,
		Up:        0,
		Unhealthy: 3,
	}

	var got healthcheck.HostStats
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestHealthCheckServer_ReturnsCorrectStatsAndCorrectHTTPCodeForHostnameOnPartOfPeersDown(t *testing.T) {
	t.Parallel()

	hs := newTestHealthServer(t)
	hs.UpstreamsForHost = getUpstreamsForHost
	hs.NginxUpstreams = getUpstreamsFromNGINXPartiallyUp

	resp, err := http.Get(hs.URL + "probe/bar.tea.com") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}

	want := healthcheck.HostStats{
		Total:     3,
		Up:        1,
		Unhealthy: 2,
	}

	var got healthcheck.HostStats
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestHealthCheckServer_RespondsWithHTTPErrCodeOnNotExistingHostname(t *testing.T) {
	t.Parallel()

	hs := newTestHealthServer(t)
	hs.UpstreamsForHost = getUpstreamsForHost
	hs.NginxUpstreams = getUpstreamsFromNGINXNotExistingHost

	resp, err := http.Get(hs.URL + "probe/foo.mocha.com") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNotFound {
		t.Error(resp.StatusCode)
	}
}

func TestHealthCheckServer_RespondsWithCorrectHTTPStatusCodeOnErrorFromNGINXAPI(t *testing.T) {
	t.Parallel()

	hs := newTestHealthServer(t)
	hs.UpstreamsForHost = getUpstreamsForHost
	hs.NginxUpstreams = getUpstreamsFromNGINXErrorFromAPI

	resp, err := http.Get(hs.URL + "probe/foo.tea.com") //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusInternalServerError {
		t.Error(resp.StatusCode)
	}
}

// getUpstreamsForHost is a helper func faking response from IC.
func getUpstreamsForHost(host string) []string {
	upstreams := map[string][]string{
		"foo.tea.com": {"upstream1", "upstream2"},
		"bar.tea.com": {"upstream1"},
	}
	u, ok := upstreams[host]
	if !ok {
		return []string{}
	}
	return u
}

// getUpstreamsFromNGINXAllUP is a helper func used
// for faking response data from NGINX API. It responds
// with all upstreams and 'peers' in 'Up' state.
//
// Upstreams retrieved using NGINX API client:
// foo.tea.com -> upstream1, upstream2
// bar.tea.com -> upstream2
func getUpstreamsFromNGINXAllUp() (*client.Upstreams, error) {
	ups := client.Upstreams{
		"upstream1": client.Upstream{
			Peers: []client.Peer{
				{State: "Up"},
				{State: "Up"},
				{State: "Up"},
			},
		},
		"upstream2": client.Upstream{
			Peers: []client.Peer{
				{State: "Up"},
				{State: "Up"},
				{State: "Up"},
			},
		},
		"upstream3": client.Upstream{
			Peers: []client.Peer{
				{State: "Up"},
				{State: "Up"},
				{State: "Up"},
			},
		},
	}
	return &ups, nil
}

// getUpstreamsFromNGINXAllUnhealthy is a helper func used
// for faking response data from NGINX API. It responds
// with all upstreams and 'peers' in 'Down' (Unhealthy) state.
//
// Upstreams retrieved using NGINX API client:
// foo.tea.com -> upstream1, upstream2
// bar.tea.com -> upstream2
func getUpstreamsFromNGINXAllUnhealthy() (*client.Upstreams, error) {
	ups := client.Upstreams{
		"upstream1": client.Upstream{
			Peers: []client.Peer{
				{State: "Down"},
				{State: "Down"},
				{State: "Down"},
			},
		},
		"upstream2": client.Upstream{
			Peers: []client.Peer{
				{State: "Down"},
				{State: "Down"},
				{State: "Down"},
			},
		},
		"upstream3": client.Upstream{
			Peers: []client.Peer{
				{State: "Down"},
				{State: "Down"},
				{State: "Down"},
			},
		},
	}
	return &ups, nil
}

// getUpstreamsFromNGINXPartiallyUp is a helper func used
// for faking response data from NGINX API. It responds
// with some upstreams and 'peers' in 'Down' (Unhealthy) state,
// and some upstreams and 'peers' in 'Up' state.
//
// Upstreams retrieved using NGINX API client
// foo.tea.com -> upstream1, upstream2
// bar.tea.com -> upstream2
func getUpstreamsFromNGINXPartiallyUp() (*client.Upstreams, error) {
	ups := client.Upstreams{
		"upstream1": client.Upstream{
			Peers: []client.Peer{
				{State: "Down"},
				{State: "Down"},
				{State: "Up"},
			},
		},
		"upstream2": client.Upstream{
			Peers: []client.Peer{
				{State: "Down"},
				{State: "Down"},
				{State: "Up"},
			},
		},
		"upstream3": client.Upstream{
			Peers: []client.Peer{
				{State: "Down"},
				{State: "Up"},
				{State: "Down"},
			},
		},
	}
	return &ups, nil
}

// getUpstreamsFromNGINXNotExistingHost is a helper func used
// for faking response data from NGINX API. It responds
// with empty upstreams on a request for not existing host.
func getUpstreamsFromNGINXNotExistingHost() (*client.Upstreams, error) {
	ups := client.Upstreams{}
	return &ups, nil
}

// getUpstreamsFromNGINXErrorFromAPI is a helper func used
// for faking err response from NGINX API client.
func getUpstreamsFromNGINXErrorFromAPI() (*client.Upstreams, error) {
	return nil, errors.New("nginx api error")
}
