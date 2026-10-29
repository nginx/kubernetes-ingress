//go:build e2e

package framework

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // Ginkgo DSL
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck // Gomega DSL
)

// Polling for Eventually-based waits; there are no fixed sleeps in the specs.
const (
	PollInterval = 50 * time.Millisecond
	WaitTimeout  = 2 * time.Minute // covers first-time backend image pulls
)

// Request is an outgoing request plus the TLS settings used to send it.
type Request struct {
	*http.Request
	// TLS starts as InsecureSkipVerify with SNI taken from the URL host; options may change it.
	TLS *tls.Config
	err error
}

// RequestOption customizes a request sent with Sandbox.Get.
type RequestOption func(*Request)

// Response is a fully read HTTP response.
type Response struct {
	Status int
	Header http.Header
	Body   string
	TLS    *tls.ConnectionState
}

// Header sets a request header. "Host" overrides the Host header only (not the TLS SNI).
func Header(key, value string) RequestOption {
	return func(r *Request) {
		if strings.EqualFold(key, "Host") {
			r.Host = value
			return
		}
		r.Header.Set(key, value)
	}
}

// BasicAuth sets HTTP basic auth credentials.
func BasicAuth(user, pass string) RequestOption {
	return func(r *Request) { r.SetBasicAuth(user, pass) }
}

// Method sets the HTTP method (default GET).
func Method(m string) RequestOption {
	return func(r *Request) { r.Method = m }
}

// Body sets the request body.
func Body(b string) RequestOption {
	return func(r *Request) {
		r.Body = io.NopCloser(strings.NewReader(b))
		r.ContentLength = int64(len(b))
	}
}

// ServerName sets the TLS SNI independently of the URL host.
func ServerName(sni string) RequestOption {
	return func(r *Request) { r.TLS.ServerName = sni }
}

// ClientCert presents a client certificate from PEM files (paths relative to tests/data are resolved by the caller).
func ClientCert(certFile, keyFile string) RequestOption {
	return func(r *Request) {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			r.err = err
			return
		}
		r.TLS.Certificates = []tls.Certificate{c}
	}
}

// Get sends a request through the shared controller: the connection always goes to the NIC
// NodePorts while the URL host is used for the Host header and SNI, so specs use URLs like
// http://<vs-host>/path. Dropped connections (reset/EOF), the signature of NGINX reloads
// closing in-flight connections, are counted per sandbox.
func (s *Sandbox) Get(ctx context.Context, url string, opts ...RequestOption) (*Response, error) {
	hr, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	r := &Request{Request: hr, TLS: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test certificates are self-signed
	for _, o := range opts {
		o(r)
	}
	if r.err != nil {
		return nil, r.err
	}
	resp, err := s.f.httpClient(r.TLS).Do(r.Request)
	if err != nil {
		s.countDrop(err)
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	s.countDrop(err)
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: string(body), TLS: resp.TLS}, err
}

func (f *Framework) httpClient(tlsCfg *tls.Config) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				port := f.HTTPPort
				if strings.HasSuffix(addr, ":443") {
					port = f.HTTPSPort
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(f.Address, port))
			},
			TLSClientConfig:   tlsCfg,
			DisableKeepAlives: true, // every request sees the current NGINX workers
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (s *Sandbox) countDrop(err error) {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		s.connDrops.Add(1)
	}
}

// EventuallyStatus polls url until it returns code and returns that response's body.
func (s *Sandbox) EventuallyStatus(ctx context.Context, url string, code int, opts ...RequestOption) string {
	GinkgoHelper()
	return s.EventuallyResponse(ctx, url, func(g Gomega, r *Response) {
		g.Expect(r.Status).To(Equal(code), "GET %s: %s", url, r.Body)
	}, opts...).Body
}

// EventuallyResponse polls url until check passes on the response, and returns that response.
func (s *Sandbox) EventuallyResponse(ctx context.Context, url string, check func(Gomega, *Response), opts ...RequestOption) *Response {
	GinkgoHelper()
	var last *Response
	Eventually(func(g Gomega) {
		r, err := s.Get(ctx, url, opts...)
		g.Expect(err).NotTo(HaveOccurred())
		check(g, r)
		last = r
	}).WithContext(ctx).WithTimeout(WaitTimeout).WithPolling(PollInterval).Should(Succeed())
	return last
}
