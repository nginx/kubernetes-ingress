package version2

import "testing"

func BenchmarkExecuteVirtualServerTemplate(b *testing.B) {
	executor, err := NewTemplateExecutor("nginx-plus.virtualserver.tmpl", "nginx-plus.transportserver.tmpl", "oidc.tmpl")
	if err != nil {
		b.Fatal(err)
	}
	cfg := vsConfig()

	b.ResetTimer()
	for range b.N {
		_, err := executor.ExecuteVirtualServerTemplate(&cfg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExecuteVirtualServerTemplateOSS(b *testing.B) {
	executor, err := NewTemplateExecutor("nginx.virtualserver.tmpl", "nginx.transportserver.tmpl", "")
	if err != nil {
		b.Fatal(err)
	}
	cfg := vsConfig()

	b.ResetTimer()
	for range b.N {
		_, err := executor.ExecuteVirtualServerTemplate(&cfg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExecuteTransportServerTemplate(b *testing.B) {
	executor, err := NewTemplateExecutor("nginx-plus.virtualserver.tmpl", "nginx-plus.transportserver.tmpl", "oidc.tmpl")
	if err != nil {
		b.Fatal(err)
	}
	cfg := tsConfig()

	b.ResetTimer()
	for range b.N {
		_, err := executor.ExecuteTransportServerTemplate(&cfg)
		if err != nil {
			b.Fatal(err)
		}
	}
}
