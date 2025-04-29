package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"regexp"
	"testing"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
	pkgversion "k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLogFormats(t *testing.T) {
	testCases := []struct {
		name   string
		format string
		wantre string
	}{
		{
			name:   "glog format message",
			format: "glog",
			wantre: `^I\d{8}\s\d+:\d+:\d+.\d{6}\s+\d+\s\w+\.go:\d+\]\s.*\s$`,
		},
		{
			name:   "json format message",
			format: "json",
			wantre: `^{"time":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+.*","level":"INFO","source":\{"file":"[^"]+\.go","line":\d+\},"msg":".*}`,
		},
		{
			name:   "text format message",
			format: "text",
			wantre: `^time=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+.*level=\w+\ssource=[^:]+\.go:\d+\smsg=\w+`,
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			ctx := initLogger(tc.format, levels.LevelInfo, &buf)
			l := nl.LoggerFromContext(ctx)
			l.Log(ctx, levels.LevelInfo, "test")
			got := buf.String()
			re := regexp.MustCompile(tc.wantre)
			if !re.MatchString(got) {
				t.Errorf("\ngot:\n%q\nwant:\n%q", got, tc.wantre)
			}
		})
	}
}

func TestK8sVersionValidation(t *testing.T) {
	testCases := []struct {
		name        string
		kubeVersion string
	}{
		{
			name:        "Earliest version 1.22.0",
			kubeVersion: "1.22.0",
		},
		{
			name:        "Minor version 1.22.5",
			kubeVersion: "1.22.5",
		},
		{
			name:        "Close to current 1.32.0",
			kubeVersion: "1.32.0",
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// setup logger
			l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
			ctx := nl.ContextWithLogger(context.Background(), l)

			// setup kube client with version
			clientset := fake.NewSimpleClientset()
			fakeDiscovery, _ := clientset.Discovery().(*fakediscovery.FakeDiscovery)
			fakeDiscovery.FakedServerVersion = &pkgversion.Info{GitVersion: tc.kubeVersion}

			// run test
			err := validateKubernetesVersionInfo(ctx, clientset)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

func TestK8sVersionValidationBad(t *testing.T) {
	testCases := []struct {
		name        string
		kubeVersion string
	}{
		{
			name:        "Before earliest version 1.21.0",
			kubeVersion: "1.21.0",
		},
		{
			name:        "Empty version",
			kubeVersion: "",
		},
		{
			name:        "Garbage",
			kubeVersion: "xyzabc",
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// setup logger
			l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
			ctx := nl.ContextWithLogger(context.Background(), l)

			// setup kube client with version
			clientset := fake.NewSimpleClientset()
			fakeDiscovery, _ := clientset.Discovery().(*fakediscovery.FakeDiscovery)
			fakeDiscovery.FakedServerVersion = &pkgversion.Info{GitVersion: tc.kubeVersion}

			// run test
			err := validateKubernetesVersionInfo(ctx, clientset)
			if err == nil {
				t.Error("Wanted an error here")
			}
		})
	}
}
