package nginx

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
)

type Transport struct{}

func (c Transport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewBufferString("42")),
		Header:     make(http.Header),
	}, nil
}

func getTestHTTPClient() *http.Client {
	ts := Transport{}
	tClient := &http.Client{
		Transport: ts,
	}
	return tClient
}

func TestVerifyClient(t *testing.T) {
	t.Parallel()
	c := verifyClient{
		client:  getTestHTTPClient(),
		timeout: 25 * time.Millisecond,
	}

	configVersion, err := c.GetConfigVersion()
	if err != nil {
		t.Errorf("error getting config version: %v", err)
	}
	if configVersion != 42 {
		t.Errorf("got bad config version, expected 42 got %v", configVersion)
	}

	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	err = c.WaitForCorrectVersion(l, 43)
	if err == nil {
		t.Error("expected error from WaitForCorrectVersion ")
	}
	err = c.WaitForCorrectVersion(l, 42)
	if err != nil {
		t.Errorf("error waiting for config version: %v", err)
	}
}

func TestConfigWriter(t *testing.T) {
	t.Parallel()
	cw, err := newVerifyConfigGenerator()
	if err != nil {
		t.Fatalf("error instantiating ConfigWriter: %v", err)
	}
	config, err := cw.GenerateVersionConfig(1)
	if err != nil {
		t.Errorf("error generating version config: %v", err)
	}
	if !strings.Contains(string(config), "configVersion") {
		t.Errorf("configVersion endpoint not set. config contents: %v", string(config))
	}
}
