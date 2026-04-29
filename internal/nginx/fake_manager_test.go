package nginx

import (
	"context"
	"testing"
)

func TestFakeManagerVersionOSS(t *testing.T) {
	t.Parallel()
	fm := NewFakeManager(context.Background(), "/etc/nginx", false)
	v := fm.Version()
	if v.IsPlus {
		t.Error("expected OSS version when nginxPlus is false")
	}
}

func TestFakeManagerVersionPlus(t *testing.T) {
	t.Parallel()
	fm := NewFakeManager(context.Background(), "/etc/nginx", true)
	v := fm.Version()
	if !v.IsPlus {
		t.Error("expected Plus version when nginxPlus is true")
	}
}
