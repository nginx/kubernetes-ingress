package glog

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
)

func TestGlogFormat(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(New(&buf, nil))
	l.Info("hello")
	got := buf.String()
	wantre := `^\w\d{8}\s\d+:\d+:\d+.\d{6}\s+\d+\s\w+\.go:\d+\]\s.*\s$`
	re := regexp.MustCompile(wantre)
	if !re.MatchString(got) {
		t.Errorf("\ngot:\n%q\nwant:\n%q", got, wantre)
	}
}

func TestGlogLogLevels(t *testing.T) {
	testCases := []struct {
		name   string
		level  slog.Level
		wantre string
	}{
		{
			name:   "Trace level log message",
			level:  levels.LevelTrace,
			wantre: `^I\d{8}\s\d+:\d+:\d+.\d{6}\s+\d+\s\w+\.go:\d+\]\s.*\s$`,
		},
		{
			name:   "Debug level log message",
			level:  levels.LevelDebug,
			wantre: `^I\d{8}\s\d+:\d+:\d+.\d{6}\s+\d+\s\w+\.go:\d+\]\s.*\s$`,
		},
		{
			name:   "Info level log message",
			level:  levels.LevelInfo,
			wantre: `^I\d{8}\s\d+:\d+:\d+.\d{6}\s+\d+\s\w+\.go:\d+\]\s.*\s$`,
		},
		{
			name:   "Warning level log message",
			level:  levels.LevelWarning,
			wantre: `^W\d{8}\s\d+:\d+:\d+.\d{6}\s+\d+\s\w+\.go:\d+\]\s.*\s$`,
		},
		{
			name:   "Error level log message",
			level:  levels.LevelError,
			wantre: `^E\d{8}\s\d+:\d+:\d+.\d{6}\s+\d+\s\w+\.go:\d+\]\s.*\s$`,
		},
		{
			name:   "Fatal level log message",
			level:  levels.LevelFatal,
			wantre: `^F\d{8}\s\d+:\d+:\d+.\d{6}\s+\d+\s\w+\.go:\d+\]\s.*\s$`,
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := slog.New(New(&buf, &Options{Level: tc.level}))
			l.Log(context.Background(), tc.level, "test")
			got := buf.String()
			re := regexp.MustCompile(tc.wantre)
			if !re.MatchString(got) {
				t.Errorf("\ngot:\n%q\nwant:\n%q", got, tc.wantre)
			}
		})
	}
}

func TestGlogDefaultLevel(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(New(&buf, nil))

	l.Debug("test")
	if got := buf.Len(); got != 0 {
		t.Errorf("got buf.Len() = %d, want 0", got)
	}
}

func TestGlogHigherLevel(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(New(&buf, &Options{Level: levels.LevelError}))

	l.Info("test")
	if got := buf.Len(); got != 0 {
		t.Errorf("got buf.Len() = %d, want 0", got)
	}
}

func TestGlogRecordAttrs(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(New(&buf, &Options{Level: levels.LevelError}))
	l.Log(context.Background(), levels.LevelError, "something failed", "resource_namespace", "my-namespace")
	got := buf.String()
	wantre := `resource_namespace=my-namespace something failed`
	re := regexp.MustCompile(wantre)
	if !re.MatchString(got) {
		t.Errorf("\ngot:\n%q\nwant match:\n%q", got, wantre)
	}
}

func TestGlogWithAttrsChaining(t *testing.T) {
	var buf bytes.Buffer
	h := New(&buf, &Options{Level: levels.LevelInfo})
	h2 := h.WithAttrs([]slog.Attr{slog.String("a", "1")})
	h3 := h2.WithAttrs([]slog.Attr{slog.String("b", "2")})
	l := slog.New(h3)
	l.Log(context.Background(), levels.LevelInfo, "chained")
	got := buf.String()
	wantre := `a=1 b=2 chained`
	re := regexp.MustCompile(wantre)
	if !re.MatchString(got) {
		t.Errorf("\ngot:\n%q\nwant match:\n%q", got, wantre)
	}
	buf.Reset()
	l2 := slog.New(h)
	l2.Log(context.Background(), levels.LevelInfo, "original")
	got = buf.String()
	re = regexp.MustCompile(`a=1|b=2`)
	if re.MatchString(got) {
		t.Errorf("original handler should not have attrs, got: %q", got)
	}
}

func TestGlogHandlerAndRecordAttrsCombined(t *testing.T) {
	var buf bytes.Buffer
	h := New(&buf, &Options{Level: levels.LevelError})
	h2 := h.WithAttrs([]slog.Attr{slog.String("handler_key", "handler_val")})
	l := slog.New(h2)
	l.Log(context.Background(), levels.LevelError, "combined", "record_key", "record_val")
	got := buf.String()
	wantre := `handler_key=handler_val record_key=record_val combined`
	re := regexp.MustCompile(wantre)
	if !re.MatchString(got) {
		t.Errorf("\ngot:\n%q\nwant match:\n%q", got, wantre)
	}
}
