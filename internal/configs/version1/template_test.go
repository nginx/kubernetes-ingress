package version1

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
	"text/template"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/nginx/kubernetes-ingress/internal/configs/commonhelpers"
	"github.com/nginx/kubernetes-ingress/internal/nginx"
)

var fakeManager = nginx.NewFakeManager("/etc/nginx")

func TestMain(m *testing.M) {
	v := m.Run()

	// After all tests have run `go-snaps` will sort snapshots
	snaps.Clean(m, snaps.CleanOpts{Sort: true})

	os.Exit(v)
}

func TestExecuteTemplate_FailsOnBogusMainTemplatePath(t *testing.T) {
	t.Parallel()

	_, err := NewTemplateExecutor("bogus-tmpl-path", "nginx.ingress.tmpl")
	if err == nil {
		t.Fatal(err)
	}
}

func TestExecuteTemplate_FailsOnBogusIngressTemplatePath(t *testing.T) {
	t.Parallel()

	_, err := NewTemplateExecutor("nginx-plus.tmpl", "bogus-tmpl-path")
	if err == nil {
		t.Fatal(err)
	}
}

func TestExecuteMainTemplateForNGINXPlusMGMTProxyHost(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgWithMGMTProxyWithNoAuth)
	if err != nil {
		t.Error(err)
	}

	if !strings.Contains(buf.String(), "proxy proxy.example.com;") {
		t.Errorf("want %q in generated config", "proxy proxy.example.com;")
	}

	snaps.MatchSnapshot(t, buf.String())
	t.Log(buf.String())
}

func TestExecuteMainTemplateForNGINXPlusMGMTProxyUser(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgWithMGMTProxyWithUser)
	if err != nil {
		t.Error(err)
	}

	if !strings.Contains(buf.String(), "proxy_username user;") {
		t.Errorf("want %q in generated config", "proxy_username user;")
	}

	snaps.MatchSnapshot(t, buf.String())
	t.Log(buf.String())
}

func TestExecuteMainTemplateForNGINXPlusMGMTProxyUserAndPass(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgWithMGMTProxyWithUserAndPass)
	if err != nil {
		t.Error(err)
	}

	if !strings.Contains(buf.String(), "proxy_username user;") {
		t.Errorf("want %q in generated config", "proxy_username user;")
	}

	if !strings.Contains(buf.String(), "proxy_password pass;") {
		t.Errorf("want %q in generated config", "proxy_password pass;")
	}

	snaps.MatchSnapshot(t, buf.String())
	t.Log(buf.String())
}

func TestExecuteMainTemplateForNGINXPlus(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfg)
	if err != nil {
		t.Error(err)
	}
	snaps.MatchSnapshot(t, buf.String())
	t.Log(buf.String())
}

func TestExecuteMainTemplateForNGINX(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfg)
	if err != nil {
		t.Error(err)
	}
	snaps.MatchSnapshot(t, buf.String())
	t.Log(buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXPlus(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfg)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINX(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfg)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXPlusWithRegexAnnotationCaseSensitiveModifier(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgWithRegExAnnotationCaseSensitive)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}

	wantLocation := "~ \"^/tea/[A-Z0-9]{3}\""
	if !strings.Contains(buf.String(), wantLocation) {
		t.Errorf("want %q in generated config", wantLocation)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXPlusWithRegexAnnotationCaseInsensitiveModifier(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgWithRegExAnnotationCaseInsensitive)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}

	wantLocation := "~* \"^/tea/[A-Z0-9]{3}\""
	if !strings.Contains(buf.String(), wantLocation) {
		t.Errorf("want %q in generated config", wantLocation)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXPlusWithRegexAnnotationExactMatchModifier(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgWithRegExAnnotationExactMatch)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}

	wantLocation := "= \"/tea\""
	if !strings.Contains(buf.String(), wantLocation) {
		t.Errorf("want %q in generated config", wantLocation)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXPlusWithRegexAnnotationEmpty(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgWithRegExAnnotationEmptyString)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}

	wantLocation := "/tea"
	if !strings.Contains(buf.String(), wantLocation) {
		t.Errorf("want %q in generated config", wantLocation)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMergeableIngressForNGINXPlus(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgMasterMinionNGINXPlus)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	want := "location /coffee {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	want = "location /tea {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMergeableIngressForNGINXPlusWithMasterPathRegex(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgMasterMinionNGINXPlusMasterMinions)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	want := "location /coffee {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	want = "location /tea {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMergeableIngressWithOneMinionWithPathRegexAnnotation(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgMasterMinionNGINXPlusMinionWithPathRegexAnnotation)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	// Observe location /coffee updated with regex
	want := "location ~* \"^/coffee\" {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	// Observe location /tea not updated with regex
	want = "location /tea {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMergeableIngressWithSecondMinionWithPathRegexAnnotation(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgMasterMinionNGINXPlusSecondMinionWithPathRegexAnnotation)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	// Observe location /coffee not updated
	want := "location /coffee {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	// Observe location /tea updated with regex
	want = "location ~ \"^/tea\" {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMergeableIngressForNGINXPlusWithPathRegexAnnotationOnMaster(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgMasterMinionNGINXPlusMasterWithPathRegexAnnotation)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}

	want := "location /coffee {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	want = "location /tea {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMergeableIngressForNGINXPlusWithPathRegexAnnotationOnMasterAndMinions(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgMasterMinionNGINXPlusMasterAndAllMinionsWithPathRegexAnnotation)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}

	want := "location ~* \"^/coffee\""
	if !strings.Contains(buf.String(), want) {
		t.Errorf("did not get %q in generated config", want)
	}
	want = "location ~* \"^/tea\""
	if !strings.Contains(buf.String(), want) {
		t.Errorf("did not get %q in generated config", want)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMergeableIngressForNGINXPlusWithPathRegexAnnotationOnMinionsNotOnMaster(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgMasterMinionNGINXPlusMasterWithoutPathRegexMinionsWithPathRegexAnnotation)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}

	want := "location ~* \"^/coffee\" {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	want = "location ~ \"^/tea\" {"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in generated config", want)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithCustomTLSPassthroughPort(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgCustomTLSPassthroughPort)
	t.Log(buf.String())
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 8443;",
		"listen [::]:8443;",
		"proxy_pass $dest_internal_passthrough",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXPlusWithCustomTLSPassthroughPort(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgCustomTLSPassthroughPort)
	t.Log(buf.String())
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 8443;",
		"listen [::]:8443;",
		"proxy_pass $dest_internal_passthrough",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithoutCustomTLSPassthroughPort(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgDefaultTLSPassthroughPort)
	t.Log(buf.String())
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 443;",
		"listen [::]:443;",
		"proxy_pass $dest_internal_passthrough",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXPlusWithoutCustomTLSPassthroughPort(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgDefaultTLSPassthroughPort)
	t.Log(buf.String())
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 443;",
		"listen [::]:443;",
		"proxy_pass $dest_internal_passthrough",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXTLSPassthroughDisabled(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgWithoutTLSPassthrough)
	t.Log(buf.String())
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	unwantDirectives := []string{
		"listen 8443;",
		"listen [::]:8443;",
		"proxy_pass $dest_internal_passthrough",
	}

	mainConf := buf.String()
	for _, want := range unwantDirectives {
		if strings.Contains(mainConf, want) {
			t.Errorf("unwant %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXPlusTLSPassthroughPortDisabled(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgWithoutTLSPassthrough)
	t.Log(buf.String())
	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	unwantDirectives := []string{
		"listen 443;",
		"listen [::]:443;",
		"proxy_pass $dest_internal_passthrough",
	}

	mainConf := buf.String()
	for _, want := range unwantDirectives {
		if strings.Contains(mainConf, want) {
			t.Errorf("unwant %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithCustomDefaultHTTPAndHTTPSListenerPorts(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgCustomDefaultHTTPAndHTTPSListenerPorts)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 8083 default_server;",
		"listen [::]:8083 default_server;",
		"listen 8443 ssl default_server;",
		"listen [::]:8443 ssl default_server;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXPlusWithCustomDefaultHTTPAndHTTPSListenerPorts(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgCustomDefaultHTTPAndHTTPSListenerPorts)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 8083 default_server;",
		"listen [::]:8083 default_server;",
		"listen 8443 ssl default_server;",
		"listen [::]:8443 ssl default_server;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithoutCustomDefaultHTTPAndHTTPSListenerPorts(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfg)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 80 default_server;",
		"listen [::]:80 default_server;",
		"listen 443 ssl default_server;",
		"listen [::]:443 ssl default_server;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXPlusWithoutCustomDefaultHTTPAndHTTPSListenerPorts(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfg)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 80 default_server;",
		"listen [::]:80 default_server;",
		"listen 443 ssl default_server;",
		"listen [::]:443 ssl default_server;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithCustomDefaultHTTPListenerPort(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgCustomDefaultHTTPListenerPort)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 8083 default_server;",
		"listen [::]:8083 default_server;",
		"listen 443 ssl default_server;",
		"listen [::]:443 ssl default_server;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithCustomDefaultHTTPSListenerPort(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgCustomDefaultHTTPSListenerPort)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 80 default_server;",
		"listen [::]:80 default_server;",
		"listen 8443 ssl default_server;",
		"listen [::]:8443 ssl default_server;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXPlusWithCustomDefaultHTTPListenerPort(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgCustomDefaultHTTPListenerPort)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 8083 default_server;",
		"listen [::]:8083 default_server;",
		"listen 443 ssl default_server;",
		"listen [::]:443 ssl default_server;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXPlusWithCustomDefaultHTTPSListenerPort(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgCustomDefaultHTTPSListenerPort)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 80 default_server;",
		"listen [::]:80 default_server;",
		"listen 8443 ssl default_server;",
		"listen [::]:8443 ssl default_server;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithHTTP2On(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgHTTP2On)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 443 ssl default_server;",
		"listen [::]:443 ssl default_server;",
		"http2 on;",
	}

	unwantDirectives := []string{
		"listen 443 ssl default_server http2;",
		"listen [::]:443 ssl default_server http2;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}

	for _, want := range unwantDirectives {
		if strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXPlusWithHTTP2On(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgHTTP2On)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 443 ssl default_server;",
		"listen [::]:443 ssl default_server;",
		"http2 on;",
	}

	unwantDirectives := []string{
		"listen 443 ssl default_server http2;",
		"listen [::]:443 ssl default_server http2;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}

	for _, want := range unwantDirectives {
		if strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithHTTP2Off(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfg)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 443 ssl default_server;",
		"listen [::]:443 ssl default_server;",
	}

	unwantDirectives := []string{
		"http2 on;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}

	for _, want := range unwantDirectives {
		if strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXPlusWithHTTP2Off(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfg)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"listen 443 ssl default_server;",
		"listen [::]:443 ssl default_server;",
	}

	unwantDirectives := []string{
		"http2 on;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}

	for _, want := range unwantDirectives {
		if strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithZoneSyncEnabledDefaultPort(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgWithZoneSyncEnabledDefaultPort)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"zone_sync;",
		"zone_sync_server nginx-ingress-headless.nginx-ingress.svc.cluster.local:12345 resolve;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithZoneSyncEnabledCustomPort(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgWithZoneSyncEnabledCustomPort)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"zone_sync;",
		"zone_sync_server nginx-ingress-headless.nginx-ingress.svc.cluster.local:1337 resolve;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithZoneSyncEnabledCustomResolverAddress(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgWithZoneSyncEnabledCustomResolverAddress)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"resolver example.com",
		"zone_sync;",
		"zone_sync_server nginx-ingress-headless.nginx-ingress.svc.cluster.local:12345 resolve;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithZoneSyncEnabledCustomResolverAddressAndValid(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgWithZoneSyncEnabledCustomResolverAddressAndValid)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"resolver example.com valid",
		"zone_sync;",
		"zone_sync_server nginx-ingress-headless.nginx-ingress.svc.cluster.local:1223 resolve;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithZoneSyncEnabledCustomResolverAddressAndValidAndIPV6Off(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgWithZoneSyncEnabledCustomResolverAddressAndValidAndIPV6Off)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"resolver example.com valid=20s ipv6=off;",
		"zone_sync;",
		"zone_sync_server nginx-ingress-headless.nginx-ingress.svc.cluster.local:1223 resolve;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMainForNGINXWithOtel(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusMainTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, mainCfgWithOTel)
	t.Log(buf.String())

	if err != nil {
		t.Fatalf("Failed to write template %v", err)
	}

	wantDirectives := []string{
		"otel_exporter {",
		"endpoint https://otel-collector:4317;",
		"header X-Custom-Header \"custom-value\";",
		"otel_service_name nginx-ingress-controller:nginx;",
		"otel_trace on;",
	}

	mainConf := buf.String()
	for _, want := range wantDirectives {
		if !strings.Contains(mainConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXWithProxySetHeadersAnnotationWithDefaultValue(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	testCases := []struct {
		masterAnnotations map[string]string
		coffeeAnnotations map[string]string
		teaAnnotations    map[string]string
		wantCoffeeHeaders []string
		wantTeaHeaders    []string
	}{
		{
			masterAnnotations: map[string]string{
				"nginx.org/proxy-set-headers": "X-Forwarded-ABC",
			},
			wantCoffeeHeaders: []string{
				`proxy_set_header X-Forwarded-ABC $http_x_forwarded_abc;`,
			},
			wantTeaHeaders: []string{
				`proxy_set_header X-Forwarded-ABC $http_x_forwarded_abc;`,
			},
		},
	}

	for _, tc := range testCases {
		buf := &bytes.Buffer{}
		ingressCfg := createProxySetHeaderIngressConfig(tc.masterAnnotations, tc.coffeeAnnotations, tc.teaAnnotations)

		err := tmpl.Execute(buf, ingressCfg)
		if err != nil {
			t.Fatal(err)
		}

		for _, wantHeader := range tc.wantCoffeeHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated coffee config", wantHeader)
			}
		}

		for _, wantHeader := range tc.wantTeaHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated tea config", wantHeader)
			}
		}
		snaps.MatchSnapshot(t, buf.String())
	}
}

func TestExecuteTemplate_ForIngressForNGINXMasterWithProxySetHeadersAnnotationWithCustomValue(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	testCases := []struct {
		masterAnnotations map[string]string
		coffeeAnnotations map[string]string
		teaAnnotations    map[string]string
		wantCoffeeHeaders []string
		wantTeaHeaders    []string
	}{
		{
			masterAnnotations: map[string]string{
				"nginx.org/proxy-set-headers": "X-Forwarded-ABC: valueABC",
			},
			wantCoffeeHeaders: []string{
				`proxy_set_header X-Forwarded-ABC "valueABC";`,
			},
			wantTeaHeaders: []string{
				`proxy_set_header X-Forwarded-ABC "valueABC";`,
			},
		},
	}

	for _, tc := range testCases {
		buf := &bytes.Buffer{}
		ingressCfg := createProxySetHeaderIngressConfig(tc.masterAnnotations, tc.coffeeAnnotations, tc.teaAnnotations)

		err := tmpl.Execute(buf, ingressCfg)
		if err != nil {
			t.Fatal(err)
		}

		for _, wantHeader := range tc.wantCoffeeHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated coffee config", wantHeader)
			}
		}

		for _, wantHeader := range tc.wantTeaHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated tea config", wantHeader)
			}
		}
		snaps.MatchSnapshot(t, buf.String())
	}
}

func TestExecuteTemplate_ForMergeableIngressForNGINXMasterWithoutAnnotationMinionsWithDefaultValuesWithProxySetHeadersAnnotation(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	testCases := []struct {
		masterAnnotations map[string]string
		coffeeAnnotations map[string]string
		teaAnnotations    map[string]string
		wantCoffeeHeaders []string
		wantTeaHeaders    []string
	}{
		{
			masterAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
			},
			coffeeAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
				"nginx.org/proxy-set-headers":      "X-Forwarded-Coffee",
			},
			wantCoffeeHeaders: []string{
				`proxy_set_header X-Forwarded-Coffee $http_x_forwarded_coffee;`,
			},
			teaAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
				"nginx.org/proxy-set-headers":      "X-Forwarded-Tea",
			},
			wantTeaHeaders: []string{
				`proxy_set_header X-Forwarded-Tea $http_x_forwarded_tea;`,
			},
		},
	}

	for _, tc := range testCases {
		buf := &bytes.Buffer{}
		ingressCfg := createProxySetHeaderIngressConfig(tc.masterAnnotations, tc.coffeeAnnotations, tc.teaAnnotations)

		err := tmpl.Execute(buf, ingressCfg)
		if err != nil {
			t.Fatal(err)
		}

		for _, wantHeader := range tc.wantCoffeeHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated coffee config", wantHeader)
			}
		}

		for _, wantHeader := range tc.wantTeaHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated tea config", wantHeader)
			}
		}
		snaps.MatchSnapshot(t, buf.String())
	}
}

func TestExecuteTemplate_ForMergeableIngressForProxySetHeaderAnnotation(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgMasterMinionNGINXPlusMasterWithProxySetHeaderAnnotation)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := `proxy_set_header X-Forwarded-ABC "coffee";`

	if !strings.Contains(buf.String(), wantHeader) {
		t.Errorf("expected header %q not found in generated coffee config", wantHeader)
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForMergeableIngressForNGINXMasterWithoutAnnotationMinionsWithCustomValuesProxySetHeadersAnnotation(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	testCases := []struct {
		masterAnnotations map[string]string
		coffeeAnnotations map[string]string
		teaAnnotations    map[string]string
		wantCoffeeHeaders []string
		wantTeaHeaders    []string
	}{
		{
			masterAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
			},
			coffeeAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
				"nginx.org/proxy-set-headers":      "X-Forwarded-Minion: coffee",
			},
			wantCoffeeHeaders: []string{
				`proxy_set_header X-Forwarded-Minion "coffee";`,
			},
			teaAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
				"nginx.org/proxy-set-headers":      "X-Forwarded-Minion: tea",
			},
			wantTeaHeaders: []string{
				`proxy_set_header X-Forwarded-Minion "tea";`,
			},
		},
	}

	for _, tc := range testCases {
		buf := &bytes.Buffer{}
		ingressCfg := createProxySetHeaderIngressConfig(tc.masterAnnotations, tc.coffeeAnnotations, tc.teaAnnotations)

		err := tmpl.Execute(buf, ingressCfg)
		if err != nil {
			t.Fatal(err)
		}

		for _, wantHeader := range tc.wantCoffeeHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated coffee config", wantHeader)
			}
		}

		for _, wantHeader := range tc.wantTeaHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated tea config", wantHeader)
			}
		}
		snaps.MatchSnapshot(t, buf.String())
	}
}

func TestExecuteTemplate_ForMergeableIngressForNGINXMasterWithoutAnnotationMinionsWithDifferentHeadersForProxySetHeadersAnnotation(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	testCases := []struct {
		masterAnnotations map[string]string
		coffeeAnnotations map[string]string
		teaAnnotations    map[string]string
		wantCoffeeHeaders []string
		wantTeaHeaders    []string
	}{
		{
			masterAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
			},
			coffeeAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
				"nginx.org/proxy-set-headers":      "X-Forwarded-Coffee: mocha",
			},
			wantCoffeeHeaders: []string{
				`proxy_set_header X-Forwarded-Coffee "mocha";`,
			},
			teaAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
				"nginx.org/proxy-set-headers":      "X-Forwarded-Tea: green",
			},
			wantTeaHeaders: []string{
				`proxy_set_header X-Forwarded-Tea "green";`,
			},
		},
	}

	for _, tc := range testCases {
		buf := &bytes.Buffer{}
		ingressCfg := createProxySetHeaderIngressConfig(tc.masterAnnotations, tc.coffeeAnnotations, tc.teaAnnotations)

		err := tmpl.Execute(buf, ingressCfg)
		if err != nil {
			t.Fatal(err)
		}

		for _, wantHeader := range tc.wantCoffeeHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated coffee config", wantHeader)
			}
		}

		for _, wantHeader := range tc.wantTeaHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated tea config", wantHeader)
			}
		}
		snaps.MatchSnapshot(t, buf.String())
	}
}

func TestExecuteTemplate_ForMergeableIngressForNGINXMasterWithAnnotationForProxySetHeadersAnnotation(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	testCases := []struct {
		masterAnnotations map[string]string
		coffeeAnnotations map[string]string
		teaAnnotations    map[string]string
		wantCoffeeHeaders []string
		wantTeaHeaders    []string
	}{
		{
			masterAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
				"nginx.org/proxy-set-headers":      "X-Forwarded-ABC",
			},
			coffeeAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
			},
			wantCoffeeHeaders: []string{
				`proxy_set_header X-Forwarded-ABC $http_x_forwarded_abc;`,
			},
			teaAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
			},
			wantTeaHeaders: []string{
				`proxy_set_header X-Forwarded-ABC $http_x_forwarded_abc;`,
			},
		},
	}

	for _, tc := range testCases {
		buf := &bytes.Buffer{}
		ingressCfg := createProxySetHeaderIngressConfig(tc.masterAnnotations, tc.coffeeAnnotations, tc.teaAnnotations)

		err := tmpl.Execute(buf, ingressCfg)
		if err != nil {
			t.Fatal(err)
		}

		for _, wantHeader := range tc.wantCoffeeHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated coffee config", wantHeader)
			}
		}

		for _, wantHeader := range tc.wantTeaHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated tea config", wantHeader)
			}
		}
		snaps.MatchSnapshot(t, buf.String())
	}
}

func TestExecuteTemplate_ForMergeableIngressForNGINXMasterMinionsWithDifferentHeadersForProxySetHeadersAnnotation(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	testCases := []struct {
		masterAnnotations map[string]string
		coffeeAnnotations map[string]string
		teaAnnotations    map[string]string
		wantCoffeeHeaders []string
		wantTeaHeaders    []string
	}{
		{
			masterAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
				"nginx.org/proxy-set-headers":      "X-Forwarded-ABC",
			},
			coffeeAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
				"nginx.org/proxy-set-headers":      "X-Forwarded-Coffee: espresso",
			},
			wantCoffeeHeaders: []string{
				`proxy_set_header X-Forwarded-Coffee "espresso"`,
				"proxy_set_header X-Forwarded-ABC $http_x_forwarded_abc;",
			},
			teaAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
				"nginx.org/proxy-set-headers":      "X-Forwarded-Tea: chai",
			},
			wantTeaHeaders: []string{
				`proxy_set_header X-Forwarded-Tea "chai"`,
				"proxy_set_header X-Forwarded-ABC $http_x_forwarded_abc;",
			},
		},
	}

	for _, tc := range testCases {
		buf := &bytes.Buffer{}
		ingressCfg := createProxySetHeaderIngressConfig(tc.masterAnnotations, tc.coffeeAnnotations, tc.teaAnnotations)

		err := tmpl.Execute(buf, ingressCfg)
		if err != nil {
			t.Fatal(err)
		}

		for _, wantHeader := range tc.wantCoffeeHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated coffee config", wantHeader)
			}
		}

		for _, wantHeader := range tc.wantTeaHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated tea config", wantHeader)
			}
		}
		snaps.MatchSnapshot(t, buf.String())
	}
}

func TestExecuteTemplate_ForMergeableIngressForNGINXWithProxySetHeadersAnnotationForMinionOverrideMaster(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	testCases := []struct {
		masterAnnotations map[string]string
		coffeeAnnotations map[string]string
		teaAnnotations    map[string]string
		wantCoffeeHeaders []string
		wantTeaHeaders    []string
	}{
		{
			masterAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
				"nginx.org/proxy-set-headers":      "X-Forwarded-ABC",
			},
			coffeeAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
				"nginx.org/proxy-set-headers":      "X-Forwarded-ABC: coffee",
			},
			wantCoffeeHeaders: []string{
				`proxy_set_header X-Forwarded-ABC "coffee"`,
			},
			wantTeaHeaders: []string{
				"proxy_set_header X-Forwarded-ABC $http_x_forwarded_abc;",
			},
		},
	}

	for _, tc := range testCases {
		buf := &bytes.Buffer{}
		ingressCfg := createProxySetHeaderIngressConfig(tc.masterAnnotations, tc.coffeeAnnotations, tc.teaAnnotations)

		err := tmpl.Execute(buf, ingressCfg)
		if err != nil {
			t.Fatal(err)
		}

		for _, wantHeader := range tc.wantCoffeeHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated coffee config", wantHeader)
			}
		}

		for _, wantHeader := range tc.wantTeaHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated tea config", wantHeader)
			}
		}
		snaps.MatchSnapshot(t, buf.String())
	}
}

func TestExecuteTemplate_ForMergeableIngressForNGINXMasterMinionsWithMultipleDifferentHeadersForProxySetHeadersAnnotation(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	testCases := []struct {
		masterAnnotations map[string]string
		coffeeAnnotations map[string]string
		teaAnnotations    map[string]string
		wantCoffeeHeaders []string
		wantTeaHeaders    []string
	}{
		{
			masterAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
				"nginx.org/proxy-set-headers":      "X-Forwarded-ABC,BVC,Location: master",
			},
			coffeeAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
				"nginx.org/proxy-set-headers":      "X-Forwarded-Coffee: espresso,X-Forwarded-Minion: coffee, Location: minion",
			},
			wantCoffeeHeaders: []string{
				`proxy_set_header X-Forwarded-Coffee "espresso"`,
				`proxy_set_header X-Forwarded-Minion "coffee"`,
				"proxy_set_header X-Forwarded-ABC $http_x_forwarded_abc;",
				"proxy_set_header BVC $http_bvc;",
				`proxy_set_header Location "minion"`,
			},
			teaAnnotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
				"nginx.org/proxy-set-headers":      "X-Forwarded-Tea: chai",
			},
			wantTeaHeaders: []string{
				`proxy_set_header X-Forwarded-Tea "chai"`,
				"proxy_set_header X-Forwarded-ABC $http_x_forwarded_abc;",
				"proxy_set_header BVC $http_bvc;",
				`proxy_set_header Location "master"`,
			},
		},
	}

	for _, tc := range testCases {
		buf := &bytes.Buffer{}
		ingressCfg := createProxySetHeaderIngressConfig(tc.masterAnnotations, tc.coffeeAnnotations, tc.teaAnnotations)

		err := tmpl.Execute(buf, ingressCfg)
		if err != nil {
			t.Fatal(err)
		}

		for _, wantHeader := range tc.wantCoffeeHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated coffee config", wantHeader)
			}
		}

		for _, wantHeader := range tc.wantTeaHeaders {
			if !strings.Contains(buf.String(), wantHeader) {
				t.Errorf("expected header %q not found in generated tea config", wantHeader)
			}
		}
		snaps.MatchSnapshot(t, buf.String())
	}
}

func TestExecuteTemplate_ForIngressForNGINXPlusWithHTTP2On(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgHTTP2On)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	ingConf := buf.String()

	wantDirectives := []string{
		"listen 443 ssl;",
		"listen [::]:443 ssl;",
		"http2 on;",
	}

	unwantDirectives := []string{
		"listen 443 ssl http2;",
		"listen [::]:443 ssl http2;",
	}

	for _, want := range wantDirectives {
		if !strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}

	for _, want := range unwantDirectives {
		if strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXWithHTTP2On(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgHTTP2On)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	ingConf := buf.String()

	wantDirectives := []string{
		"listen 443 ssl;",
		"listen [::]:443 ssl;",
		"http2 on;",
	}

	unwantDirectives := []string{
		"listen 443 ssl http2;",
		"listen [::]:443 ssl http2;",
	}

	for _, want := range wantDirectives {
		if !strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}

	for _, want := range unwantDirectives {
		if strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXPlusWithHTTP2Off(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfg)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	ingConf := buf.String()

	wantDirectives := []string{
		"listen 443 ssl;",
		"listen [::]:443 ssl;",
	}

	unwantDirectives := []string{
		"http2 on;",
	}

	for _, want := range wantDirectives {
		if !strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}

	for _, want := range unwantDirectives {
		if strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXWithHTTP2Off(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfg)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	ingConf := buf.String()

	wantDirectives := []string{
		"listen 443 ssl;",
		"listen [::]:443 ssl;",
	}

	unwantDirectives := []string{
		"http2 on;",
	}

	for _, want := range wantDirectives {
		if !strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}

	for _, want := range unwantDirectives {
		if strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXWithRequestRateLimit(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgRequestRateLimit)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	ingConf := buf.String()

	limitReq := ingressCfgRequestRateLimit.Servers[0].Locations[0].LimitReq

	wantDirectives := []string{
		"limit_req_zone ${binary_remote_addr} zone=default/myingress:10m rate=200r/s;",
		"limit_req zone=default/myingress burst=" + strconv.Itoa(limitReq.Burst) + " delay=" + strconv.Itoa(limitReq.Delay) + ";",
		"limit_req_status " + strconv.Itoa(limitReq.RejectCode) + ";",
		"limit_req_dry_run on;",
		"limit_req_log_level info;",
	}

	for _, want := range wantDirectives {
		if !strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXWithRequestRateLimitMinions(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgRequestRateLimitMinions)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	ingConf := buf.String()

	limitReqTea := ingressCfgRequestRateLimitMinions.Servers[0].Locations[0].LimitReq
	limitReqCoffee := ingressCfgRequestRateLimitMinions.Servers[0].Locations[1].LimitReq

	wantDirectives := []string{
		"limit_req_zone ${binary_remote_addr} zone=default/tea-minion:10m rate=200r/s;",
		"limit_req_zone ${binary_remote_addr} zone=default/coffee-minion:20m rate=400r/s;",
		"limit_req zone=" + limitReqTea.Zone + " burst=" + strconv.Itoa(limitReqTea.Burst) + " delay=" + strconv.Itoa(limitReqTea.Delay) + ";",
		"limit_req zone=" + limitReqCoffee.Zone + " burst=" + strconv.Itoa(limitReqCoffee.Burst) + " nodelay;",
		"limit_req_status " + strconv.Itoa(limitReqTea.RejectCode) + ";",
		"limit_req_status " + strconv.Itoa(limitReqCoffee.RejectCode) + ";",
		"limit_req_log_level " + limitReqTea.LogLevel + ";",
		"limit_req_log_level " + limitReqCoffee.LogLevel + ";",
		"limit_req_dry_run on;",
	}

	for _, want := range wantDirectives {
		if !strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXPlusWithRequestRateLimit(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgRequestRateLimit)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	ingConf := buf.String()

	limitReq := ingressCfgRequestRateLimit.Servers[0].Locations[0].LimitReq

	wantDirectives := []string{
		"limit_req_zone ${binary_remote_addr} zone=default/myingress:10m rate=200r/s;",
		"limit_req zone=default/myingress burst=" + strconv.Itoa(limitReq.Burst) + " delay=" + strconv.Itoa(limitReq.Delay) + ";",
		"limit_req_status " + strconv.Itoa(limitReq.RejectCode) + ";",
		"limit_req_dry_run on;",
		"limit_req_log_level info;",
	}

	for _, want := range wantDirectives {
		if !strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXPlusWithRequestRateLimitMinions(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	err := tmpl.Execute(buf, ingressCfgRequestRateLimitMinions)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	ingConf := buf.String()

	limitReqTea := ingressCfgRequestRateLimitMinions.Servers[0].Locations[0].LimitReq
	limitReqCoffee := ingressCfgRequestRateLimitMinions.Servers[0].Locations[1].LimitReq

	wantDirectives := []string{
		"limit_req_zone ${binary_remote_addr} zone=default/tea-minion:10m rate=200r/s;",
		"limit_req_zone ${binary_remote_addr} zone=default/coffee-minion:20m rate=400r/s;",
		"limit_req zone=" + limitReqTea.Zone + " burst=" + strconv.Itoa(limitReqTea.Burst) + " delay=" + strconv.Itoa(limitReqTea.Delay) + ";",
		"limit_req zone=" + limitReqCoffee.Zone + " burst=" + strconv.Itoa(limitReqCoffee.Burst) + " nodelay;",
		"limit_req_status " + strconv.Itoa(limitReqTea.RejectCode) + ";",
		"limit_req_status " + strconv.Itoa(limitReqCoffee.RejectCode) + ";",
		"limit_req_log_level " + limitReqTea.LogLevel + ";",
		"limit_req_log_level " + limitReqCoffee.LogLevel + ";",
		"limit_req_dry_run on;",
	}

	for _, want := range wantDirectives {
		if !strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func TestExecuteTemplate_ForIngressForNGINXPlusWithRequestRateLimitZoneSync(t *testing.T) {
	t.Parallel()

	tmpl := newNGINXPlusIngressTmpl(t)
	buf := &bytes.Buffer{}

	ingressCfg := IngressNginxConfig{
		Ingress: Ingress{
			Name:      "myingress",
			Namespace: "default",
		},
		Servers: []Server{
			{
				Name: "test.example.com",
				Locations: []Location{
					{
						Path:     "/",
						Upstream: testUpstream,
						LimitReq: &LimitReq{
							Zone:       "default/myingress_sync",
							Burst:      100,
							RejectCode: 429,
						},
					},
				},
			},
		},
		LimitReqZones: []LimitReqZone{
			{
				Name: "default/zone1_sync",
				Key:  "${binary_remote_addr}",
				Size: "10m",
				Rate: "200r/s",
				Sync: true,
			},
		},
	}

	err := tmpl.Execute(buf, ingressCfg)
	t.Log(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	ingConf := buf.String()

	wantDirectives := []string{
		"limit_req_zone ${binary_remote_addr} zone=default/zone1_sync:10m rate=200r/s sync;",
		"limit_req zone=default/myingress_sync burst=100;",
	}

	for _, want := range wantDirectives {
		if !strings.Contains(ingConf, want) {
			t.Errorf("want %q in generated config", want)
		}
	}
	snaps.MatchSnapshot(t, buf.String())
}

func newNGINXPlusIngressTmpl(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("nginx-plus.ingress.tmpl").Funcs(helperFunctions).ParseFiles("nginx-plus.ingress.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}

func newNGINXIngressTmpl(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("nginx.ingress.tmpl").Funcs(helperFunctions).ParseFiles("nginx.ingress.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}

func newNGINXPlusMainTmpl(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("nginx-plus.tmpl").Funcs(helperFunctions).ParseFiles("nginx-plus.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}

func newNGINXMainTmpl(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("nginx.tmpl").Funcs(helperFunctions).ParseFiles("nginx.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}

var (
	// Ingress Config example without added annotations
	ingressCfg = IngressNginxConfig{
		Servers: []Server{
			{
				Name:         "test.example.com",
				ServerTokens: "off",
				StatusZone:   "test.example.com",
				JWTAuth: &JWTAuth{
					Key:                  "/etc/nginx/secrets/key.jwk",
					Realm:                "closed site",
					Token:                "$cookie_auth_token",
					RedirectLocationName: "@login_url-default-cafe-ingress",
				},
				SSL:               true,
				SSLCertificate:    "secret.pem",
				SSLCertificateKey: "secret.pem",
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				Locations: []Location{
					{
						Path:                "/tea",
						Upstream:            testUpstream,
						ProxyConnectTimeout: "10s",
						ProxyReadTimeout:    "10s",
						ProxySendTimeout:    "10s",
						ClientMaxBodySize:   "2m",
						JWTAuth: &JWTAuth{
							Key:   "/etc/nginx/secrets/location-key.jwk",
							Realm: "closed site",
							Token: "$cookie_auth_token",
						},
						MinionIngress: &Ingress{
							Name:      "tea-minion",
							Namespace: "default",
						},
					},
				},
				HealthChecks: map[string]HealthCheck{"test": healthCheck},
				JWTRedirectLocations: []JWTRedirectLocation{
					{
						Name:     "@login_url-default-cafe-ingress",
						LoginURL: "https://test.example.com/login",
					},
				},
				AppProtectEnable: "on",
				AppProtectPolicy: "/etc/nginx/waf/nac-policies/default-dataguard-alarm",
				AppProtectLogConfs: []string{
					"/etc/nginx/waf/nac-logconfs/test_logconf syslog:server=127.0.0.1:514",
					"/etc/nginx/waf/nac-logconfs/test_logconf2",
				},
				AppProtectLogEnable:          "on",
				AppProtectDosEnable:          "on",
				AppProtectDosPolicyFile:      "/test/policy.json",
				AppProtectDosLogConfFile:     "/test/logConf.json",
				AppProtectDosLogEnable:       true,
				AppProtectDosMonitorURI:      "/path/to/monitor",
				AppProtectDosMonitorProtocol: "http1",
				AppProtectDosMonitorTimeout:  30,
				AppProtectDosName:            "testdos",
				AppProtectDosAccessLogDst:    "/var/log/dos",
				AppProtectDosAllowListPath:   "/etc/nginx/dos/allowlist/default_test.example.com",
			},
		},
		Upstreams: []Upstream{testUpstream},
		Keepalive: "16",
		Ingress: Ingress{
			Name:      "cafe-ingress",
			Namespace: "default",
		},
	}

	// Ingress Config example with path-regex annotation value "case_sensitive"
	ingressCfgWithRegExAnnotationCaseSensitive = IngressNginxConfig{
		Servers: []Server{
			{
				Name:         "test.example.com",
				ServerTokens: "off",
				StatusZone:   "test.example.com",
				JWTAuth: &JWTAuth{
					Key:                  "/etc/nginx/secrets/key.jwk",
					Realm:                "closed site",
					Token:                "$cookie_auth_token",
					RedirectLocationName: "@login_url-default-cafe-ingress",
				},
				SSL:               true,
				SSLCertificate:    "secret.pem",
				SSLCertificateKey: "secret.pem",
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				Locations: []Location{
					{
						Path:                "/tea/[A-Z0-9]{3}",
						Upstream:            testUpstream,
						ProxyConnectTimeout: "10s",
						ProxyReadTimeout:    "10s",
						ProxySendTimeout:    "10s",
						ClientMaxBodySize:   "2m",
						JWTAuth: &JWTAuth{
							Key:   "/etc/nginx/secrets/location-key.jwk",
							Realm: "closed site",
							Token: "$cookie_auth_token",
						},
						MinionIngress: &Ingress{
							Name:      "tea-minion",
							Namespace: "default",
						},
					},
				},
				HealthChecks: map[string]HealthCheck{"test": healthCheck},
				JWTRedirectLocations: []JWTRedirectLocation{
					{
						Name:     "@login_url-default-cafe-ingress",
						LoginURL: "https://test.example.com/login",
					},
				},
			},
		},
		Upstreams: []Upstream{testUpstream},
		Keepalive: "16",
		Ingress: Ingress{
			Name:        "cafe-ingress",
			Namespace:   "default",
			Annotations: map[string]string{"nginx.org/path-regex": "case_sensitive"},
		},
	}

	// Ingress Config example with path-regex annotation value "case_insensitive"
	ingressCfgWithRegExAnnotationCaseInsensitive = IngressNginxConfig{
		Servers: []Server{
			{
				Name:         "test.example.com",
				ServerTokens: "off",
				StatusZone:   "test.example.com",
				JWTAuth: &JWTAuth{
					Key:                  "/etc/nginx/secrets/key.jwk",
					Realm:                "closed site",
					Token:                "$cookie_auth_token",
					RedirectLocationName: "@login_url-default-cafe-ingress",
				},
				SSL:               true,
				SSLCertificate:    "secret.pem",
				SSLCertificateKey: "secret.pem",
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				Locations: []Location{
					{
						Path:                "/tea/[A-Z0-9]{3}",
						Upstream:            testUpstream,
						ProxyConnectTimeout: "10s",
						ProxyReadTimeout:    "10s",
						ProxySendTimeout:    "10s",
						ClientMaxBodySize:   "2m",
						JWTAuth: &JWTAuth{
							Key:   "/etc/nginx/secrets/location-key.jwk",
							Realm: "closed site",
							Token: "$cookie_auth_token",
						},
						MinionIngress: &Ingress{
							Name:      "tea-minion",
							Namespace: "default",
						},
					},
				},
				HealthChecks: map[string]HealthCheck{"test": healthCheck},
				JWTRedirectLocations: []JWTRedirectLocation{
					{
						Name:     "@login_url-default-cafe-ingress",
						LoginURL: "https://test.example.com/login",
					},
				},
			},
		},
		Upstreams: []Upstream{testUpstream},
		Keepalive: "16",
		Ingress: Ingress{
			Name:        "cafe-ingress",
			Namespace:   "default",
			Annotations: map[string]string{"nginx.org/path-regex": "case_insensitive"},
		},
	}

	// Ingress Config example with path-regex annotation value "exact"
	ingressCfgWithRegExAnnotationExactMatch = IngressNginxConfig{
		Servers: []Server{
			{
				Name:         "test.example.com",
				ServerTokens: "off",
				StatusZone:   "test.example.com",
				JWTAuth: &JWTAuth{
					Key:                  "/etc/nginx/secrets/key.jwk",
					Realm:                "closed site",
					Token:                "$cookie_auth_token",
					RedirectLocationName: "@login_url-default-cafe-ingress",
				},
				SSL:               true,
				SSLCertificate:    "secret.pem",
				SSLCertificateKey: "secret.pem",
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				Locations: []Location{
					{
						Path:                "/tea",
						Upstream:            testUpstream,
						ProxyConnectTimeout: "10s",
						ProxyReadTimeout:    "10s",
						ProxySendTimeout:    "10s",
						ClientMaxBodySize:   "2m",
						JWTAuth: &JWTAuth{
							Key:   "/etc/nginx/secrets/location-key.jwk",
							Realm: "closed site",
							Token: "$cookie_auth_token",
						},
						MinionIngress: &Ingress{
							Name:      "tea-minion",
							Namespace: "default",
						},
					},
				},
				HealthChecks: map[string]HealthCheck{"test": healthCheck},
				JWTRedirectLocations: []JWTRedirectLocation{
					{
						Name:     "@login_url-default-cafe-ingress",
						LoginURL: "https://test.example.com/login",
					},
				},
			},
		},
		Upstreams: []Upstream{testUpstream},
		Keepalive: "16",
		Ingress: Ingress{
			Name:        "cafe-ingress",
			Namespace:   "default",
			Annotations: map[string]string{"nginx.org/path-regex": "exact"},
		},
	}

	// Ingress Config example with path-regex annotation value of an empty string
	ingressCfgWithRegExAnnotationEmptyString = IngressNginxConfig{
		Servers: []Server{
			{
				Name:         "test.example.com",
				ServerTokens: "off",
				StatusZone:   "test.example.com",
				JWTAuth: &JWTAuth{
					Key:                  "/etc/nginx/secrets/key.jwk",
					Realm:                "closed site",
					Token:                "$cookie_auth_token",
					RedirectLocationName: "@login_url-default-cafe-ingress",
				},
				SSL:               true,
				SSLCertificate:    "secret.pem",
				SSLCertificateKey: "secret.pem",
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				Locations: []Location{
					{
						Path:                "/tea",
						Upstream:            testUpstream,
						ProxyConnectTimeout: "10s",
						ProxyReadTimeout:    "10s",
						ProxySendTimeout:    "10s",
						ClientMaxBodySize:   "2m",
						JWTAuth: &JWTAuth{
							Key:   "/etc/nginx/secrets/location-key.jwk",
							Realm: "closed site",
							Token: "$cookie_auth_token",
						},
						MinionIngress: &Ingress{
							Name:      "tea-minion",
							Namespace: "default",
						},
					},
				},
				HealthChecks: map[string]HealthCheck{"test": healthCheck},
				JWTRedirectLocations: []JWTRedirectLocation{
					{
						Name:     "@login_url-default-cafe-ingress",
						LoginURL: "https://test.example.com/login",
					},
				},
			},
		},
		Upstreams: []Upstream{testUpstream},
		Keepalive: "16",
		Ingress: Ingress{
			Name:        "cafe-ingress",
			Namespace:   "default",
			Annotations: map[string]string{"nginx.org/path-regex": ""},
		},
	}

	mainCfg = MainConfig{
		StaticSSLPath:                      fakeManager.GetSecretsDir(),
		DefaultHTTPListenerPort:            80,
		DefaultHTTPSListenerPort:           443,
		ServerNamesHashMaxSize:             "512",
		ServerTokens:                       "off",
		WorkerProcesses:                    "auto",
		WorkerCPUAffinity:                  "auto",
		WorkerShutdownTimeout:              "1m",
		WorkerConnections:                  "1024",
		WorkerRlimitNofile:                 "65536",
		LogFormat:                          []string{"$remote_addr", "$remote_user"},
		LogFormatEscaping:                  "default",
		StreamSnippets:                     []string{"# comment"},
		StreamLogFormat:                    []string{"$remote_addr", "$remote_user"},
		StreamLogFormatEscaping:            "none",
		ResolverAddresses:                  []string{"example.com", "127.0.0.1"},
		ResolverIPV6:                       false,
		ResolverValid:                      "10s",
		ResolverTimeout:                    "15s",
		KeepaliveTimeout:                   "65s",
		KeepaliveRequests:                  100,
		VariablesHashBucketSize:            256,
		VariablesHashMaxSize:               1024,
		NginxVersion:                       nginx.NewVersion("nginx version: nginx/1.27.2 (nginx-plus-r33)"),
		AppProtectLoadModule:               true,
		AppProtectV5LoadModule:             false,
		AppProtectV5EnforcerAddr:           "",
		AppProtectFailureModeAction:        "pass",
		AppProtectCompressedRequestsAction: "pass",
		AppProtectCookieSeed:               "ABCDEFGHIJKLMNOP",
		AppProtectCPUThresholds:            "high=low=100",
		AppProtectPhysicalMemoryThresholds: "high=low=100",
		AppProtectReconnectPeriod:          "10",
		AppProtectDosLoadModule:            true,
		AppProtectDosLogFormat: []string{
			"$remote_addr - $remote_user [$time_local]",
			"\"$request\" $status $body_bytes_sent ",
			"\"$http_referer\" \"$http_user_agent\"",
		},
		AppProtectDosLogFormatEscaping: "json",
		AppProtectDosArbFqdn:           "arb.test.server.com",
		AccessLog:                      "/dev/stdout main",
	}

	mainCfgHTTP2On = MainConfig{
		StaticSSLPath:                      fakeManager.GetSecretsDir(),
		DefaultHTTPListenerPort:            80,
		DefaultHTTPSListenerPort:           443,
		HTTP2:                              true,
		ServerNamesHashMaxSize:             "512",
		ServerTokens:                       "off",
		WorkerProcesses:                    "auto",
		WorkerCPUAffinity:                  "auto",
		WorkerShutdownTimeout:              "1m",
		WorkerConnections:                  "1024",
		WorkerRlimitNofile:                 "65536",
		LogFormat:                          []string{"$remote_addr", "$remote_user"},
		LogFormatEscaping:                  "default",
		StreamSnippets:                     []string{"# comment"},
		StreamLogFormat:                    []string{"$remote_addr", "$remote_user"},
		StreamLogFormatEscaping:            "none",
		ResolverAddresses:                  []string{"example.com", "127.0.0.1"},
		ResolverIPV6:                       false,
		ResolverValid:                      "10s",
		ResolverTimeout:                    "15s",
		KeepaliveTimeout:                   "65s",
		KeepaliveRequests:                  100,
		VariablesHashBucketSize:            256,
		VariablesHashMaxSize:               1024,
		NginxVersion:                       nginx.NewVersion("nginx version: nginx/1.27.2 (nginx-plus-r33)"),
		AppProtectLoadModule:               true,
		AppProtectV5LoadModule:             false,
		AppProtectV5EnforcerAddr:           "",
		AppProtectFailureModeAction:        "pass",
		AppProtectCompressedRequestsAction: "pass",
		AppProtectCookieSeed:               "ABCDEFGHIJKLMNOP",
		AppProtectCPUThresholds:            "high=low=100",
		AppProtectPhysicalMemoryThresholds: "high=low=100",
		AppProtectReconnectPeriod:          "10",
		AppProtectDosLoadModule:            true,
		AppProtectDosLogFormat:             []string{},
		AppProtectDosArbFqdn:               "arb.test.server.com",
		AccessLog:                          "/dev/stdout main",
	}

	mainCfgCustomTLSPassthroughPort = MainConfig{
		StaticSSLPath:           fakeManager.GetSecretsDir(),
		ServerNamesHashMaxSize:  "512",
		ServerTokens:            "off",
		WorkerProcesses:         "auto",
		WorkerCPUAffinity:       "auto",
		WorkerShutdownTimeout:   "1m",
		WorkerConnections:       "1024",
		WorkerRlimitNofile:      "65536",
		LogFormat:               []string{"$remote_addr", "$remote_user"},
		LogFormatEscaping:       "default",
		StreamSnippets:          []string{"# comment"},
		StreamLogFormat:         []string{"$remote_addr", "$remote_user"},
		StreamLogFormatEscaping: "none",
		ResolverAddresses:       []string{"example.com", "127.0.0.1"},
		ResolverIPV6:            false,
		ResolverValid:           "10s",
		ResolverTimeout:         "15s",
		KeepaliveTimeout:        "65s",
		KeepaliveRequests:       100,
		VariablesHashBucketSize: 256,
		VariablesHashMaxSize:    1024,
		TLSPassthrough:          true,
		TLSPassthroughPort:      8443,
		NginxVersion:            nginx.NewVersion("nginx version: nginx/1.27.2 (nginx-plus-r33)"),
		AccessLog:               "/dev/stdout main",
	}

	mainCfgWithoutTLSPassthrough = MainConfig{
		StaticSSLPath:           fakeManager.GetSecretsDir(),
		ServerNamesHashMaxSize:  "512",
		ServerTokens:            "off",
		WorkerProcesses:         "auto",
		WorkerCPUAffinity:       "auto",
		WorkerShutdownTimeout:   "1m",
		WorkerConnections:       "1024",
		WorkerRlimitNofile:      "65536",
		LogFormat:               []string{"$remote_addr", "$remote_user"},
		LogFormatEscaping:       "default",
		StreamSnippets:          []string{"# comment"},
		StreamLogFormat:         []string{"$remote_addr", "$remote_user"},
		StreamLogFormatEscaping: "none",
		ResolverAddresses:       []string{"example.com", "127.0.0.1"},
		ResolverIPV6:            false,
		ResolverValid:           "10s",
		ResolverTimeout:         "15s",
		KeepaliveTimeout:        "65s",
		KeepaliveRequests:       100,
		VariablesHashBucketSize: 256,
		VariablesHashMaxSize:    1024,
		TLSPassthrough:          false,
		TLSPassthroughPort:      8443,
		NginxVersion:            nginx.NewVersion("nginx version: nginx/1.27.2 (nginx-plus-r33)"),
		AccessLog:               "/dev/stdout main",
	}

	mainCfgDefaultTLSPassthroughPort = MainConfig{
		StaticSSLPath:           fakeManager.GetSecretsDir(),
		ServerNamesHashMaxSize:  "512",
		ServerTokens:            "off",
		WorkerProcesses:         "auto",
		WorkerCPUAffinity:       "auto",
		WorkerShutdownTimeout:   "1m",
		WorkerConnections:       "1024",
		WorkerRlimitNofile:      "65536",
		LogFormat:               []string{"$remote_addr", "$remote_user"},
		LogFormatEscaping:       "default",
		StreamSnippets:          []string{"# comment"},
		StreamLogFormat:         []string{"$remote_addr", "$remote_user"},
		StreamLogFormatEscaping: "none",
		ResolverAddresses:       []string{"example.com", "127.0.0.1"},
		ResolverIPV6:            false,
		ResolverValid:           "10s",
		ResolverTimeout:         "15s",
		KeepaliveTimeout:        "65s",
		KeepaliveRequests:       100,
		VariablesHashBucketSize: 256,
		VariablesHashMaxSize:    1024,
		TLSPassthrough:          true,
		TLSPassthroughPort:      443,
		NginxVersion:            nginx.NewVersion("nginx version: nginx/1.27.2 (nginx-plus-r33)"),
		AccessLog:               "/dev/stdout main",
	}

	mainCfgCustomDefaultHTTPAndHTTPSListenerPorts = MainConfig{
		StaticSSLPath:            fakeManager.GetSecretsDir(),
		DefaultHTTPListenerPort:  8083,
		DefaultHTTPSListenerPort: 8443,
		ServerNamesHashMaxSize:   "512",
		ServerTokens:             "off",
		WorkerProcesses:          "auto",
		WorkerCPUAffinity:        "auto",
		WorkerShutdownTimeout:    "1m",
		WorkerConnections:        "1024",
		WorkerRlimitNofile:       "65536",
		LogFormat:                []string{"$remote_addr", "$remote_user"},
		LogFormatEscaping:        "default",
		StreamSnippets:           []string{"# comment"},
		StreamLogFormat:          []string{"$remote_addr", "$remote_user"},
		StreamLogFormatEscaping:  "none",
		ResolverAddresses:        []string{"example.com", "127.0.0.1"},
		ResolverIPV6:             false,
		ResolverValid:            "10s",
		ResolverTimeout:          "15s",
		KeepaliveTimeout:         "65s",
		KeepaliveRequests:        100,
		VariablesHashBucketSize:  256,
		VariablesHashMaxSize:     1024,
		NginxVersion:             nginx.NewVersion("nginx version: nginx/1.27.2 (nginx-plus-r33)"),
		AccessLog:                "/dev/stdout main",
	}

	mainCfgCustomDefaultHTTPListenerPort = MainConfig{
		StaticSSLPath:            fakeManager.GetSecretsDir(),
		DefaultHTTPListenerPort:  8083,
		DefaultHTTPSListenerPort: 443,
		ServerNamesHashMaxSize:   "512",
		ServerTokens:             "off",
		WorkerProcesses:          "auto",
		WorkerCPUAffinity:        "auto",
		WorkerShutdownTimeout:    "1m",
		WorkerConnections:        "1024",
		WorkerRlimitNofile:       "65536",
		LogFormat:                []string{"$remote_addr", "$remote_user"},
		LogFormatEscaping:        "default",
		StreamSnippets:           []string{"# comment"},
		StreamLogFormat:          []string{"$remote_addr", "$remote_user"},
		StreamLogFormatEscaping:  "none",
		ResolverAddresses:        []string{"example.com", "127.0.0.1"},
		ResolverIPV6:             false,
		ResolverValid:            "10s",
		ResolverTimeout:          "15s",
		KeepaliveTimeout:         "65s",
		KeepaliveRequests:        100,
		VariablesHashBucketSize:  256,
		VariablesHashMaxSize:     1024,
		NginxVersion:             nginx.NewVersion("nginx version: nginx/1.27.2 (nginx-plus-r33)"),
		AccessLog:                "/dev/stdout main",
	}

	mainCfgCustomDefaultHTTPSListenerPort = MainConfig{
		StaticSSLPath:            fakeManager.GetSecretsDir(),
		DefaultHTTPListenerPort:  80,
		DefaultHTTPSListenerPort: 8443,
		ServerNamesHashMaxSize:   "512",
		ServerTokens:             "off",
		WorkerProcesses:          "auto",
		WorkerCPUAffinity:        "auto",
		WorkerShutdownTimeout:    "1m",
		WorkerConnections:        "1024",
		WorkerRlimitNofile:       "65536",
		LogFormat:                []string{"$remote_addr", "$remote_user"},
		LogFormatEscaping:        "default",
		StreamSnippets:           []string{"# comment"},
		StreamLogFormat:          []string{"$remote_addr", "$remote_user"},
		StreamLogFormatEscaping:  "none",
		ResolverAddresses:        []string{"example.com", "127.0.0.1"},
		ResolverIPV6:             false,
		ResolverValid:            "10s",
		ResolverTimeout:          "15s",
		KeepaliveTimeout:         "65s",
		KeepaliveRequests:        100,
		VariablesHashBucketSize:  256,
		VariablesHashMaxSize:     1024,
		NginxVersion:             nginx.NewVersion("nginx version: nginx/1.27.2 (nginx-plus-r33)"),
		AccessLog:                "/dev/stdout main",
	}

	mainCfgWithMGMTProxyWithNoAuth = MainConfig{
		StaticSSLPath: fakeManager.GetSecretsDir(),

		MGMTConfig: MGMTConfig{
			ProxyHost: "proxy.example.com",
		},
	}

	mainCfgWithMGMTProxyWithUser = MainConfig{
		StaticSSLPath: fakeManager.GetSecretsDir(),

		MGMTConfig: MGMTConfig{
			ProxyHost: "proxy.example.com",
			ProxyUser: "user",
		},
	}

	mainCfgWithMGMTProxyWithUserAndPass = MainConfig{
		StaticSSLPath: fakeManager.GetSecretsDir(),

		MGMTConfig: MGMTConfig{
			ProxyHost: "proxy.example.com",
			ProxyUser: "user",
			ProxyPass: "pass",
		},
	}

	mainCfgWithZoneSyncEnabledDefaultPort = MainConfig{
		ZoneSyncConfig: ZoneSyncConfig{
			Enable: true,
			Port:   12345,
			Domain: "nginx-ingress-headless.nginx-ingress.svc.cluster.local",
		},
		NginxVersion: nginx.NewVersion("nginx version: nginx/1.27.2 (nginx-plus-r33)"),
	}

	mainCfgWithZoneSyncEnabledCustomPort = MainConfig{
		ZoneSyncConfig: ZoneSyncConfig{
			Enable: true,
			Port:   1337,
			Domain: "nginx-ingress-headless.nginx-ingress.svc.cluster.local",
		},
	}
	mainCfgWithZoneSyncEnabledCustomResolverAddress = MainConfig{
		ZoneSyncConfig: ZoneSyncConfig{
			Enable:            true,
			Port:              12345,
			Domain:            "nginx-ingress-headless.nginx-ingress.svc.cluster.local",
			ResolverAddresses: []string{"example.com"},
		},
	}

	mainCfgWithZoneSyncEnabledCustomResolverAddressAndValid = MainConfig{
		ZoneSyncConfig: ZoneSyncConfig{
			Enable:            true,
			Port:              1223,
			Domain:            "nginx-ingress-headless.nginx-ingress.svc.cluster.local",
			ResolverAddresses: []string{"example.com"},
			ResolverValid:     "20s",
		},
	}

	mainCfgWithZoneSyncEnabledCustomResolverAddressAndValidAndIPV6Off = MainConfig{
		ZoneSyncConfig: ZoneSyncConfig{
			Enable:            true,
			Port:              1223,
			Domain:            "nginx-ingress-headless.nginx-ingress.svc.cluster.local",
			ResolverAddresses: []string{"example.com"},
			ResolverValid:     "20s",
			ResolverIPV6:      commonhelpers.BoolToPointerBool(false),
		},
	}

	mainCfgWithOTel = MainConfig{
		MainOtelLoadModule:          true,
		MainOtelGlobalTraceEnabled:  true,
		MainOtelExporterEndpoint:    "https://otel-collector:4317",
		MainOtelExporterHeaderName:  "X-Custom-Header",
		MainOtelExporterHeaderValue: "custom-value",
		MainOtelServiceName:         "nginx-ingress-controller:nginx",
	}

	// Vars for Mergable Ingress Master - Minion tests

	coffeeUpstreamNginxPlus = Upstream{
		Name:             "default-cafe-ingress-coffee-minion-cafe.example.com-coffee-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: "512k",
		UpstreamServers: []UpstreamServer{
			{
				Address:     "10.0.0.1:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
		UpstreamLabels: UpstreamLabels{
			Service:           "coffee-svc",
			ResourceType:      "ingress",
			ResourceName:      "cafe-ingress-coffee-minion",
			ResourceNamespace: "default",
		},
	}

	teaUpstreamNGINXPlus = Upstream{
		Name:             "default-cafe-ingress-tea-minion-cafe.example.com-tea-svc-80",
		LBMethod:         "random two least_conn",
		UpstreamZoneSize: "512k",
		UpstreamServers: []UpstreamServer{
			{
				Address:     "10.0.0.2:80",
				MaxFails:    1,
				MaxConns:    0,
				FailTimeout: "10s",
			},
		},
		UpstreamLabels: UpstreamLabels{
			Service:           "tea-svc",
			ResourceType:      "ingress",
			ResourceName:      "cafe-ingress-tea-minion",
			ResourceNamespace: "default",
		},
	}

	ingressCfgMasterMinionNGINXPlus = IngressNginxConfig{
		Upstreams: []Upstream{
			coffeeUpstreamNginxPlus,
			teaUpstreamNGINXPlus,
		},
		Servers: []Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstreamNginxPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-coffee-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "coffee-svc.default.svc",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstreamNGINXPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-tea-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "tea-svc.default.svc",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HealthChecks:      make(map[string]HealthCheck),
			},
		},
		Ingress: Ingress{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
			},
		},
	}

	// ingressCfgMasterMinionNGINXPlusMasterMinions holds data to test the following scenario:
	//
	// Ingress Master - Minion
	//  - Master: with `path-regex` annotation
	//  - Minion 1 (cafe-ingress-coffee-minion): without `path-regex` annotation
	//  - Minion 2 (cafe-ingress-tea-minion): without `path-regex` annotation
	ingressCfgMasterMinionNGINXPlusMasterMinions = IngressNginxConfig{
		Upstreams: []Upstream{
			coffeeUpstreamNginxPlus,
			teaUpstreamNGINXPlus,
		},
		Servers: []Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstreamNginxPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-coffee-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "coffee-svc.default.svc",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstreamNGINXPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-tea-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "tea-svc.default.svc",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HealthChecks:      make(map[string]HealthCheck),
			},
		},
		Ingress: Ingress{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
				"nginx.org/path-regex":             "case_sensitive",
			},
		},
	}

	// ingressCfgMasterMinionNGINXPlusMinionWithPathRegexAnnotation holds data to test the following scenario:
	//
	// Ingress Master - Minion
	//  - Master: without `path-regex` annotation
	//  - Minion 1 (cafe-ingress-coffee-minion): with `path-regex` annotation
	//  - Minion 2 (cafe-ingress-tea-minion): without `path-regex` annotation
	ingressCfgMasterMinionNGINXPlusMinionWithPathRegexAnnotation = IngressNginxConfig{
		Upstreams: []Upstream{
			coffeeUpstreamNginxPlus,
			teaUpstreamNGINXPlus,
		},
		Servers: []Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstreamNginxPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-coffee-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
								"nginx.org/path-regex":             "case_insensitive",
							},
						},
						ProxySSLName: "coffee-svc.default.svc",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstreamNGINXPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-tea-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "tea-svc.default.svc",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HealthChecks:      make(map[string]HealthCheck),
			},
		},
		Ingress: Ingress{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
			},
		},
	}

	// ingressCfgMasterMinionNGINXPlusSecondMinionWithPathRegexAnnotation holds data to test the following scenario:
	//
	// Ingress Master - Minion
	//  - Master: without `path-regex` annotation
	//  - Minion 1 (cafe-ingress-coffee-minion): without `path-regex` annotation
	//  - Minion 2 (cafe-ingress-tea-minion): with `path-regex` annotation
	ingressCfgMasterMinionNGINXPlusSecondMinionWithPathRegexAnnotation = IngressNginxConfig{
		Upstreams: []Upstream{
			coffeeUpstreamNginxPlus,
			teaUpstreamNGINXPlus,
		},
		Servers: []Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstreamNginxPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-coffee-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "coffee-svc.default.svc",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstreamNGINXPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-tea-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
								"nginx.org/path-regex":             "case_sensitive",
							},
						},
						ProxySSLName: "tea-svc.default.svc",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HealthChecks:      make(map[string]HealthCheck),
			},
		},
		Ingress: Ingress{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
			},
		},
	}

	// ingressCfgMasterMinionNGINXPlusMasterWithPathRegexAnnotation holds data to test the following scenario:
	//
	// Ingress Master - Minion
	//
	//  - Master: with `path-regex` annotation
	//  - Minion 1 (cafe-ingress-coffee-minion): without `path-regex` annotation
	//  - Minion 2 (cafe-ingress-tea-minion): without `path-regex` annotation
	ingressCfgMasterMinionNGINXPlusMasterWithPathRegexAnnotation = IngressNginxConfig{
		Upstreams: []Upstream{
			coffeeUpstreamNginxPlus,
			teaUpstreamNGINXPlus,
		},
		Servers: []Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstreamNginxPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-coffee-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "coffee-svc.default.svc",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstreamNGINXPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-tea-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
							},
						},
						ProxySSLName: "tea-svc.default.svc",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HealthChecks:      make(map[string]HealthCheck),
			},
		},
		Ingress: Ingress{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
				"nginx.org/path-regex":             "case_sensitive",
			},
		},
	}

	// ingressCfgMasterMinionNGINXPlusMasterAndAllMinionsWithPathRegexAnnotation holds data to test the following scenario:
	//
	// Ingress Master - Minion
	//
	//  - Master: with `path-regex` annotation
	//  - Minion 1 (cafe-ingress-coffee-minion): with `path-regex` annotation
	//  - Minion 2 (cafe-ingress-tea-minion): with `path-regex` annotation
	ingressCfgMasterMinionNGINXPlusMasterAndAllMinionsWithPathRegexAnnotation = IngressNginxConfig{
		Upstreams: []Upstream{
			coffeeUpstreamNginxPlus,
			teaUpstreamNGINXPlus,
		},
		Servers: []Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstreamNginxPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-coffee-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
								"nginx.org/path-regex":             "case_insensitive",
							},
						},
						ProxySSLName: "coffee-svc.default.svc",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstreamNGINXPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-tea-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
								"nginx.org/path-regex":             "case_insensitive",
							},
						},
						ProxySSLName: "tea-svc.default.svc",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HealthChecks:      make(map[string]HealthCheck),
			},
		},
		Ingress: Ingress{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
				"nginx.org/path-regex":             "case_sensitive",
			},
		},
	}

	// ingressCfgMasterMinionNGINXPlusMasterWithoutPathRegexMinionsWithPathRegexAnnotation holds data to test the following scenario:
	//
	// Ingress Master - Minion
	//  - Master: without `path-regex` annotation
	//  - Minion 1 (cafe-ingress-coffee-minion): with `path-regex` annotation
	//  - Minion 2 (cafe-ingress-tea-minion): with `path-regex` annotation
	ingressCfgMasterMinionNGINXPlusMasterWithoutPathRegexMinionsWithPathRegexAnnotation = IngressNginxConfig{
		Upstreams: []Upstream{
			coffeeUpstreamNginxPlus,
			teaUpstreamNGINXPlus,
		},
		Servers: []Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstreamNginxPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-coffee-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
								"nginx.org/path-regex":             "case_insensitive",
							},
						},
						ProxySSLName: "coffee-svc.default.svc",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstreamNGINXPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-tea-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
								"nginx.org/path-regex":             "case_sensitive",
							},
						},
						ProxySSLName: "tea-svc.default.svc",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HealthChecks:      make(map[string]HealthCheck),
			},
		},
		Ingress: Ingress{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
			},
		},
	}

	// ingressCfgMasterMinionNGINXPlusMasterWithProxySetHeaderAnnotation holds data to test the following scenario:
	//
	// Ingress Master - Minion
	//
	//  - Master: without `proxy-set-headers` annotation
	//  - Minion 1 (cafe-ingress-coffee-minion): with `proxy-set-headers annotation
	//  - Minion 2 (cafe-ingress-tea-minion): with `proxy-set-headers` annotation
	ingressCfgMasterMinionNGINXPlusMasterWithProxySetHeaderAnnotation = IngressNginxConfig{
		Upstreams: []Upstream{
			coffeeUpstreamNginxPlus,
			teaUpstreamNGINXPlus,
		},
		Servers: []Server{
			{
				Name:         "cafe.example.com",
				ServerTokens: "on",
				Locations: []Location{
					{
						Path:                "/coffee",
						ServiceName:         "coffee-svc",
						Upstream:            coffeeUpstreamNginxPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-coffee-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
								"nginx.org/proxy-set-headers":      "X-Forwarded-ABC: coffee",
							},
						},
						ProxySSLName: "coffee-svc.default.svc",
					},
					{
						Path:                "/tea",
						ServiceName:         "tea-svc",
						Upstream:            teaUpstreamNGINXPlus,
						ProxyConnectTimeout: "60s",
						ProxyReadTimeout:    "60s",
						ProxySendTimeout:    "60s",
						ClientMaxBodySize:   "1m",
						ProxyBuffering:      true,
						MinionIngress: &Ingress{
							Name:      "cafe-ingress-tea-minion",
							Namespace: "default",
							Annotations: map[string]string{
								"nginx.org/mergeable-ingress-type": "minion",
								"nginx.org/proxy-set-headers":      "X-Forwarded-ABC: tea",
							},
						},
						ProxySSLName: "tea-svc.default.svc",
					},
				},
				SSL:               true,
				SSLCertificate:    "/etc/nginx/secrets/default-cafe-secret",
				SSLCertificateKey: "/etc/nginx/secrets/default-cafe-secret",
				StatusZone:        "cafe.example.com",
				HSTSMaxAge:        2592000,
				Ports:             []int{80},
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				HealthChecks:      make(map[string]HealthCheck),
			},
		},
		Ingress: Ingress{
			Name:      "cafe-ingress-master",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
			},
		},
	}

	// Ingress Config example without added annotations
	ingressCfgHTTP2On = IngressNginxConfig{
		Servers: []Server{
			{
				Name:              "test.example.com",
				ServerTokens:      "off",
				StatusZone:        "test.example.com",
				SSL:               true,
				HTTP2:             true,
				SSLCertificate:    "secret.pem",
				SSLCertificateKey: "secret.pem",
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				Locations: []Location{
					{
						Path:                "/tea",
						Upstream:            testUpstream,
						ProxyConnectTimeout: "10s",
						ProxyReadTimeout:    "10s",
						ProxySendTimeout:    "10s",
						ClientMaxBodySize:   "2m",
						MinionIngress: &Ingress{
							Name:      "tea-minion",
							Namespace: "default",
						},
					},
				},
				HealthChecks: map[string]HealthCheck{"test": healthCheck},
				JWTRedirectLocations: []JWTRedirectLocation{
					{
						Name:     "@login_url-default-cafe-ingress",
						LoginURL: "https://test.example.com/login",
					},
				},
			},
		},
		Upstreams: []Upstream{testUpstream},
		Keepalive: "16",
		Ingress: Ingress{
			Name:      "cafe-ingress",
			Namespace: "default",
		},
	}

	// Ingress Config that includes a request rate limit
	ingressCfgRequestRateLimit = IngressNginxConfig{
		Ingress: Ingress{
			Name:      "myingress",
			Namespace: "default",
		},
		Servers: []Server{
			{
				Name:         "test.example.com",
				ServerTokens: "off",
				StatusZone:   "test.example.com",
				JWTAuth: &JWTAuth{
					Key:                  "/etc/nginx/secrets/key.jwk",
					Realm:                "closed site",
					Token:                "$cookie_auth_token",
					RedirectLocationName: "@login_url-default-cafe-ingress",
				},
				SSL:               true,
				SSLCertificate:    "secret.pem",
				SSLCertificateKey: "secret.pem",
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				Locations: []Location{
					{
						Path:                "/tea",
						Upstream:            testUpstream,
						ProxyConnectTimeout: "10s",
						ProxyReadTimeout:    "10s",
						ProxySendTimeout:    "10s",
						ClientMaxBodySize:   "2m",
						JWTAuth: &JWTAuth{
							Key:   "/etc/nginx/secrets/location-key.jwk",
							Realm: "closed site",
							Token: "$cookie_auth_token",
						},
						LimitReq: &LimitReq{
							Zone:       "default/myingress",
							Burst:      100,
							Delay:      50,
							RejectCode: 429,
							DryRun:     true,
							LogLevel:   "info",
						},
					},
					{
						Path:                "/coffee",
						Upstream:            testUpstream,
						ProxyConnectTimeout: "10s",
						ProxyReadTimeout:    "10s",
						ProxySendTimeout:    "10s",
						ClientMaxBodySize:   "2m",
						JWTAuth: &JWTAuth{
							Key:   "/etc/nginx/secrets/location-key.jwk",
							Realm: "closed site",
							Token: "$cookie_auth_token",
						},
						LimitReq: &LimitReq{
							Zone:       "default/myingress",
							Burst:      100,
							Delay:      50,
							RejectCode: 429,
							DryRun:     true,
							LogLevel:   "info",
						},
					},
				},
				HealthChecks: map[string]HealthCheck{"test": healthCheck},
				JWTRedirectLocations: []JWTRedirectLocation{
					{
						Name:     "@login_url-default-cafe-ingress",
						LoginURL: "https://test.example.com/login",
					},
				},
			},
		},
		LimitReqZones: []LimitReqZone{
			{
				Name: "default/myingress",
				Key:  "${binary_remote_addr}",
				Size: "10m",
				Rate: "200r/s",
			},
		},
	}

	ingressCfgRequestRateLimitMinions = IngressNginxConfig{
		Ingress: Ingress{
			Name:      "myingress",
			Namespace: "default",
		},
		Servers: []Server{
			{
				Name:         "test.example.com",
				ServerTokens: "off",
				StatusZone:   "test.example.com",
				JWTAuth: &JWTAuth{
					Key:                  "/etc/nginx/secrets/key.jwk",
					Realm:                "closed site",
					Token:                "$cookie_auth_token",
					RedirectLocationName: "@login_url-default-cafe-ingress",
				},
				SSL:               true,
				SSLCertificate:    "secret.pem",
				SSLCertificateKey: "secret.pem",
				SSLPorts:          []int{443},
				SSLRedirect:       true,
				Locations: []Location{
					{
						Path:                "/tea",
						Upstream:            testUpstream,
						ProxyConnectTimeout: "10s",
						ProxyReadTimeout:    "10s",
						ProxySendTimeout:    "10s",
						ClientMaxBodySize:   "2m",
						JWTAuth: &JWTAuth{
							Key:   "/etc/nginx/secrets/location-key.jwk",
							Realm: "closed site",
							Token: "$cookie_auth_token",
						},
						MinionIngress: &Ingress{
							Name:      "tea-minion",
							Namespace: "default",
						},
						LimitReq: &LimitReq{
							Zone:       "default/tea-minion",
							Burst:      100,
							Delay:      10,
							LogLevel:   "info",
							DryRun:     true,
							RejectCode: 429,
						},
					},
					{
						Path:                "/coffee",
						Upstream:            testUpstream,
						ProxyConnectTimeout: "10s",
						ProxyReadTimeout:    "10s",
						ProxySendTimeout:    "10s",
						ClientMaxBodySize:   "2m",
						JWTAuth: &JWTAuth{
							Key:   "/etc/nginx/secrets/location-key.jwk",
							Realm: "closed site",
							Token: "$cookie_auth_token",
						},
						MinionIngress: &Ingress{
							Name:      "coffee-minion",
							Namespace: "default",
						},
						LimitReq: &LimitReq{
							Zone:       "default/coffee-minion",
							Burst:      200,
							NoDelay:    true,
							LogLevel:   "error",
							RejectCode: 503,
						},
					},
				},
				HealthChecks: map[string]HealthCheck{"test": healthCheck},
				JWTRedirectLocations: []JWTRedirectLocation{
					{
						Name:     "@login_url-default-cafe-ingress",
						LoginURL: "https://test.example.com/login",
					},
				},
			},
		},
		LimitReqZones: []LimitReqZone{
			{
				Name: "default/tea-minion",
				Key:  "${binary_remote_addr}",
				Size: "10m",
				Rate: "200r/s",
			},
			{
				Name: "default/coffee-minion",
				Key:  "${binary_remote_addr}",
				Size: "20m",
				Rate: "400r/s",
			},
		},
	}
)

var testUpstream = Upstream{
	Name:             "test",
	UpstreamZoneSize: "256k",
	UpstreamServers: []UpstreamServer{
		{
			Address:     "127.0.0.1:8181",
			MaxFails:    0,
			MaxConns:    0,
			FailTimeout: "1s",
			SlowStart:   "5s",
		},
	},
}

var (
	headers     = map[string]string{"Test-Header": "test-header-value"}
	healthCheck = HealthCheck{
		UpstreamName: "test",
		Fails:        1,
		Interval:     1,
		Passes:       1,
		Headers:      headers,
	}
)

func createProxySetHeaderIngressConfig(masterAnnotations map[string]string, coffeeAnnotations map[string]string, teamAnnotations map[string]string) IngressNginxConfig {
	return IngressNginxConfig{
		Servers: []Server{
			{
				Name: "cafe.example.com",
				Locations: []Location{
					{
						MinionIngress: &Ingress{
							Name:        "cafe-ingress-coffee-minion",
							Namespace:   "default",
							Annotations: coffeeAnnotations,
						},
					},
					{
						MinionIngress: &Ingress{
							Name:        "cafe-ingress-tea-minion",
							Namespace:   "default",
							Annotations: teamAnnotations,
						},
					},
				},
			},
		},
		Ingress: Ingress{
			Name:        "cafe-ingress-master",
			Namespace:   "default",
			Annotations: masterAnnotations,
		},
	}
}
