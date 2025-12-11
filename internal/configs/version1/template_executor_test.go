package version1

import (
	"strings"
	"testing"
)

func TestNewTemplateExecutor(t *testing.T) {
	t.Parallel()
	_, err := NewTemplateExecutor("nginx-plus.tmpl", "nginx-plus.ingress.tmpl")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTemplateExecutorUsesOriginalMainTemplate(t *testing.T) {
	t.Parallel()

	te := newTestTemplateExecutor(t)

	mainConfig, err := te.ExecuteMainConfigTemplate(&mainCfg)
	if err != nil {
		t.Fatal(err)
	}

	prefix := "# TEST NEW MAIN TEMPLATE"

	if strings.HasPrefix(string(mainConfig), prefix) {
		t.Errorf("Config starts with unwanted prefix: %s", prefix)
	}

	err = te.UpdateMainTemplate(&customMainTemplate)
	if err != nil {
		t.Fatal(err)
	}

	mainConfig, err = te.ExecuteMainConfigTemplate(&mainCfg)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(string(mainConfig), prefix) {
		t.Fatalf("Config does not start with prefix: %s", prefix)
	}

	// Revert to the original, main config template
	te.UseOriginalMainTemplate()

	mainConfig, err = te.ExecuteMainConfigTemplate(&mainCfg)
	if err != nil {
		t.Fatal(err)
	}

	if strings.HasPrefix(string(mainConfig), prefix) {
		t.Errorf("Config starts with invalid prefix: %s", prefix)
	}
	t.Logf("\n%s\n", string(mainConfig))
}

func TestTemplateExecutorUsesOriginalIngressTemplate(t *testing.T) {
	t.Parallel()

	te := newTestTemplateExecutor(t)
	ingressConfig, err := te.ExecuteIngressConfigTemplate(&ingressCfg)
	if err != nil {
		t.Fatal(err)
	}

	prefix := "# TEST NEW CUSTOM INGRESS TEMPLATE"

	if strings.HasPrefix(string(ingressConfig), prefix) {
		t.Fatalf("Ingress config starts with unwanted prefix: %s", prefix)
	}

	err = te.UpdateIngressTemplate(&customIngressTemplate)
	if err != nil {
		t.Fatal(err)
	}

	ingressConfig, err = te.ExecuteIngressConfigTemplate(&ingressCfg)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(string(ingressConfig), prefix) {
		t.Fatalf("Ingress config does not start with prefix: %s", prefix)
	}

	// Revert to the original, ingress config template
	te.UseOriginalIngressTemplate()

	ingressConfig, err = te.ExecuteIngressConfigTemplate(&ingressCfg)
	if err != nil {
		t.Fatal(err)
	}

	if strings.HasPrefix(string(ingressConfig), prefix) {
		t.Errorf("Ingress config starts with unwanted the prefix: %s\n", prefix)
	}
	t.Logf("\n%s\n", string(ingressConfig))
}

func newTestTemplateExecutor(t *testing.T) *TemplateExecutor {
	t.Helper()
	te, err := NewTemplateExecutor("nginx-plus.tmpl", "nginx-plus.ingress.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	return te
}

// custom Main Template represents a main-template passed via ConfigMap
var customMainTemplate = `# TEST NEW MAIN TEMPLATE
{{- /*gotype: github.com/nginx/kubernetes-ingress/internal/configs/version1.MainConfig*/ -}}
worker_processes  {{.WorkerProcesses}};
{{- if .WorkerRlimitNofile}}
worker_rlimit_nofile {{.WorkerRlimitNofile}};{{end}}
{{- if .WorkerCPUAffinity}}
worker_cpu_affinity {{.WorkerCPUAffinity}};{{end}}
{{- if .WorkerShutdownTimeout}}
worker_shutdown_timeout {{.WorkerShutdownTimeout}};{{end}}

daemon off;

error_log  stderr {{.ErrorLogLevel}};
pid        /var/lib/nginx/nginx.pid;

{{- if .AppProtectLoadModule}}
load_module modules/ngx_http_app_protect_module.so;
{{- end}}
{{- if .AppProtectDosLoadModule}}
load_module modules/ngx_http_app_protect_dos_module.so;
{{- end}}
load_module modules/ngx_fips_check_module.so;
{{- if .MainSnippets}}
{{range $value := .MainSnippets}}
{{$value}}{{end}}
{{- end}}

load_module modules/ngx_http_js_module.so;

events {
    worker_connections  {{.WorkerConnections}};
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    map_hash_max_size {{.MapHashMaxSize}};
    map_hash_bucket_size {{.MapHashBucketSize}};

    js_import /etc/nginx/njs/apikey_auth.js;
    js_set $apikey_auth_hash apikey_auth.hash;

    {{- if .HTTPSnippets}}
    {{range $value := .HTTPSnippets}}
    {{$value}}{{end}}
    {{- end}}

    {{if .LogFormat -}}
    log_format  main {{if .LogFormatEscaping}}escape={{ .LogFormatEscaping }} {{end}}
                     {{range $i, $value := .LogFormat -}}
                     {{with $value}}'{{if $i}} {{end}}{{$value}}'
                     {{end}}{{end}};
    {{- else -}}
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';
    {{- end}}

    map $upstream_trailer_grpc_status $grpc_status {
        default $upstream_trailer_grpc_status;
        '' $sent_http_grpc_status;
    }

    {{- if .DynamicSSLReloadEnabled }}
    map $nginx_version $secret_dir_path {
        default "{{ .StaticSSLPath }}";
    }
    {{- end }}

    {{- if .AppProtectDosLoadModule}}
    {{- if .AppProtectDosLogFormat}}
    log_format  log_dos {{if .AppProtectDosLogFormatEscaping}}escape={{ .AppProtectDosLogFormatEscaping }} {{end}}
                    {{range $i, $value := .AppProtectDosLogFormat -}}
                    {{with $value}}'{{if $i}} {{end}}{{$value}}'
                    {{end}}{{end}};
    {{- else }}
    log_format  log_dos ', vs_name_al=$app_protect_dos_vs_name, ip=$remote_addr, tls_fp=$app_protect_dos_tls_fp, '
                        'outcome=$app_protect_dos_outcome, reason=$app_protect_dos_outcome_reason, '
                        'ip_tls=$remote_addr:$app_protect_dos_tls_fp, ';

    {{- end}}
    {{- if .AppProtectDosArbFqdn}}
    app_protect_dos_arb_fqdn {{.AppProtectDosArbFqdn}};
    {{- end}}
    {{- end}}

    {{- if .AppProtectV5LoadModule}}
    app_protect_enforcer_address {{ .AppProtectV5EnforcerAddr }};
    {{- end}}

    access_log {{.AccessLog}};

    {{- if .LatencyMetrics}}
    log_format response_time '{"upstreamAddress":"$upstream_addr", "upstreamResponseTime":"$upstream_response_time", "proxyHost":"$proxy_host", "upstreamStatus": "$upstream_status"}';
    access_log syslog:server=unix:/var/lib/nginx/nginx-syslog.sock,nohostname,tag=nginx response_time;
    {{- end}}

    {{- if .AppProtectLoadModule}}
    {{if .AppProtectFailureModeAction}}app_protect_failure_mode_action {{.AppProtectFailureModeAction}};{{end}}
    {{if .AppProtectCompressedRequestsAction}}app_protect_compressed_requests_action {{.AppProtectCompressedRequestsAction}};{{end}}
    {{if .AppProtectCookieSeed}}app_protect_cookie_seed {{.AppProtectCookieSeed}};{{end}}
    {{if .AppProtectCPUThresholds}}app_protect_cpu_thresholds {{.AppProtectCPUThresholds}};{{end}}
    {{if .AppProtectPhysicalMemoryThresholds}}app_protect_physical_memory_util_thresholds {{.AppProtectPhysicalMemoryThresholds}};{{end}}
    {{if .AppProtectReconnectPeriod}}app_protect_reconnect_period_seconds {{.AppProtectReconnectPeriod}};{{end}}
    include /etc/nginx/waf/nac-usersigs/index.conf;
    {{- end}}

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout {{.KeepaliveTimeout}};
    keepalive_requests {{.KeepaliveRequests}};

    #gzip  on;

    server_names_hash_max_size {{.ServerNamesHashMaxSize}};
    {{if .ServerNamesHashBucketSize}}server_names_hash_bucket_size {{.ServerNamesHashBucketSize}};{{end}}

    variables_hash_bucket_size {{.VariablesHashBucketSize}};
    variables_hash_max_size {{.VariablesHashMaxSize}};

    map $request_uri $request_uri_no_args {
        "~^(?P<path>[^?]*)(\?.*)?$" $path;
    }

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }
    map $http_upgrade $vs_connection_header {
        default upgrade;
        ''      $default_connection_header;
    }
    {{- if .SSLProtocols}}
    ssl_protocols {{.SSLProtocols}};
    {{- end}}
    {{- if .SSLCiphers}}
    ssl_ciphers "{{.SSLCiphers}}";
    {{- end}}
    {{- if .SSLPreferServerCiphers}}
    ssl_prefer_server_ciphers on;
    {{- end}}
    {{- if .SSLDHParam}}
    ssl_dhparam {{.SSLDHParam}};
    {{- end}}

    {{- if .ResolverAddresses}}
    resolver {{range $resolver := .ResolverAddresses}}{{$resolver}}{{end}}{{if .ResolverValid}} valid={{.ResolverValid}}{{end}}{{if not .ResolverIPV6}} ipv6=off{{end}};
    {{- if .ResolverTimeout}}resolver_timeout {{.ResolverTimeout}};{{end}}
    {{- end}}

    {{- if .OIDC}}
    include oidc/oidc_common.conf;
    {{- end}}

    server {
        # required to support the Websocket protocol in VirtualServer/VirtualServerRoutes
        set $default_connection_header "";
        set $resource_type "";
        set $resource_name "";
        set $resource_namespace "";
        set $service "";

        listen {{ .DefaultHTTPListenerPort }} default_server{{if .ProxyProtocol}} proxy_protocol{{end}};
        {{- if not .DisableIPV6}}listen [::]:{{ .DefaultHTTPListenerPort }} default_server{{if .ProxyProtocol}} proxy_protocol{{end}};{{end}}

        {{- if .TLSPassthrough}}
        listen unix:/var/lib/nginx/passthrough-https.sock ssl default_server proxy_protocol;
        set_real_ip_from unix:;
        real_ip_header proxy_protocol;
        {{- else}}
        listen {{ .DefaultHTTPSListenerPort }} ssl default_server{{if .ProxyProtocol}} proxy_protocol{{end}};
        {{if not .DisableIPV6}}listen [::]:{{ .DefaultHTTPSListenerPort }} ssl default_server{{if .ProxyProtocol}} proxy_protocol{{end}};{{end}}
        {{- end}}

        {{- if .HTTP2}}
        http2 on;
        {{- end}}

        {{- if .SSLRejectHandshake}}
        ssl_reject_handshake on;
        {{- else}}
        ssl_certificate {{ makeSecretPath "/etc/nginx/secrets/default" .StaticSSLPath "$secret_dir_path" .DynamicSSLReloadEnabled }};
        ssl_certificate_key {{ makeSecretPath "/etc/nginx/secrets/default" .StaticSSLPath "$secret_dir_path" .DynamicSSLReloadEnabled }};
        {{- end}}

        {{- range $setRealIPFrom := .SetRealIPFrom}}
        set_real_ip_from {{$setRealIPFrom}};{{end}}
        {{- if .RealIPHeader}}real_ip_header {{.RealIPHeader}};{{end}}
        {{- if .RealIPRecursive}}real_ip_recursive on;{{end}}

        server_name _;
        server_tokens "{{.ServerTokens}}";
        {{- if .DefaultServerAccessLogOff}}
        access_log off;
        {{end -}}

        {{- if .HealthStatus}}
        location {{.HealthStatusURI}} {
            default_type text/plain;
            return 200 "healthy\n";
        }
        {{end}}

        location / {
            return {{.DefaultServerReturn}};
        }
    }

    {{- if .NginxStatus}}
    # NGINX Plus APIs
    server {
        listen {{.NginxStatusPort}};
        {{if not .DisableIPV6}}listen [::]:{{.NginxStatusPort}};{{end}}

        root /usr/share/nginx/html;

        access_log off;

        location  = /dashboard.html {
        }
        {{if .AppProtectDosLoadModule}}
        location = /dashboard-dos.html {
        }
        {{end}}
        {{range $value := .NginxStatusAllowCIDRs}}
        allow {{$value}};{{end}}

        deny all;
        location /api {
            {{if .AppProtectDosLoadModule}}
            app_protect_dos_api on;
            {{end}}
            api write=off;
        }
    }
    {{- end}}

    # NGINX Plus API over unix socket
    server {
        listen unix:/var/lib/nginx/nginx-plus-api.sock;
        access_log off;

        # $config_version_mismatch is defined in /etc/nginx/config-version.conf
        location /configVersionCheck {
            if ($config_version_mismatch) {
                return 503;
            }
            return 200;
        }

        location /api {
            api write=on;
        }
    }

    include /etc/nginx/config-version.conf;
    include /etc/nginx/conf.d/*.conf;

    server {
        listen unix:/var/lib/nginx/nginx-418-server.sock;
        access_log off;

        return 418;
    }
    {{- if .InternalRouteServer}}
    server {
        listen 443 ssl;
        {{if not .DisableIPV6}}listen [::]:443 ssl;{{end}}
        server_name {{.InternalRouteServerName}};
        ssl_certificate {{ makeSecretPath "/etc/nginx/secrets/spiffe_cert.pem" .StaticSSLPath "$secret_dir_path" .DynamicSSLReloadEnabled }};
        ssl_certificate_key {{ makeSecretPath "/etc/nginx/secrets/spiffe_key.pem" .StaticSSLPath "$secret_dir_path" .DynamicSSLReloadEnabled }};
        ssl_client_certificate /etc/nginx/secrets/spiffe_rootca.pem;
        ssl_verify_client on;
        ssl_verify_depth 25;
    }
    {{- end}}
}

stream {
    {{if .StreamLogFormat -}}
    log_format  stream-main {{if .StreamLogFormatEscaping}}escape={{ .StreamLogFormatEscaping }} {{end}}
                            {{range $i, $value := .StreamLogFormat -}}
                            {{with $value}}'{{if $i}} {{end}}{{$value}}'
                            {{end}}{{end}};
    {{- else -}}
    log_format  stream-main  '$remote_addr [$time_local] '
                      '$protocol $status $bytes_sent $bytes_received '
                      '$session_time "$ssl_preread_server_name"';
    {{- end}}

    access_log  /dev/stdout  stream-main;

    {{- range $value := .StreamSnippets}}
    {{$value}}{{end}}

    {{- if .ResolverAddresses}}
    resolver {{range $resolver := .ResolverAddresses}}{{$resolver}}{{end}}{{if .ResolverValid}} valid={{.ResolverValid}}{{end}}{{if not .ResolverIPV6}} ipv6=off{{end}};
    {{if .ResolverTimeout}}resolver_timeout {{.ResolverTimeout}};{{end}}
    {{- end}}

    map_hash_max_size {{.MapHashMaxSize}};
    {{if .MapHashBucketSize}}map_hash_bucket_size {{.MapHashBucketSize}};{{end}}

    {{- if .DynamicSSLReloadEnabled }}
    map $nginx_version $secret_dir_path {
        default "{{ .StaticSSLPath }}";
    }
    {{- end }}

    {{- if .TLSPassthrough}}
    map $ssl_preread_server_name $dest_internal_passthrough  {
        default unix:/var/lib/nginx/passthrough-https.sock;
        include /etc/nginx/tls-passthrough-hosts.conf;
    }

    server {
        listen {{.TLSPassthroughPort}}{{if .ProxyProtocol}} proxy_protocol{{end}};
        {{if not .DisableIPV6}}listen [::]:{{.TLSPassthroughPort}}{{if .ProxyProtocol}} proxy_protocol{{end}};{{end}}

        {{if .ProxyProtocol}}
        {{range $setRealIPFrom := .SetRealIPFrom}}
        set_real_ip_from {{$setRealIPFrom}};{{end}}
        {{end}}

        ssl_preread on;

        proxy_protocol on;
        proxy_pass $dest_internal_passthrough;
    }
    {{end}}

    include /etc/nginx/stream-conf.d/*.conf;
}

{{- if (.NginxVersion.PlusGreaterThanOrEqualTo "nginx-plus-r31") }}
mgmt {
    usage_report interval=0s;
}
{{- end}}
`

// custom Ingress Template represents an ingress-template passed via ConfigMap
var customIngressTemplate = `# TEST NEW CUSTOM INGRESS TEMPLATE
{{- /*gotype: github.com/nginx/kubernetes-ingress/internal/configs/version1.IngressNginxConfig*/ -}}
# configuration for {{.Ingress.Namespace}}/{{.Ingress.Name}}
{{- range $upstream := .Upstreams}}
upstream {{$upstream.Name}} {
	{{- if ne $upstream.UpstreamZoneSize "0"}}zone {{$upstream.Name}} {{$upstream.UpstreamZoneSize}};{{end}}
	{{- if $upstream.LBMethod }}
	{{$upstream.LBMethod}};
	{{- end}}
	{{- range $server := $upstream.UpstreamServers}}
	server {{$server.Address}} max_fails={{$server.MaxFails}} fail_timeout={{$server.FailTimeout}} max_conns={{$server.MaxConns}};{{end}}
	{{- if $.Keepalive}}keepalive {{$.Keepalive}};{{end}}
}
{{end -}}

{{range $limitReqZone := .LimitReqZones}}
limit_req_zone {{ $limitReqZone.Key }} zone={{ $limitReqZone.Name }}:{{$limitReqZone.Size}} rate={{$limitReqZone.Rate}};
{{end}}

{{range $server := .Servers}}
server {
	{{- if $server.SpiffeCerts}}
	listen 443 ssl;
	{{- if not $server.DisableIPV6}}listen [::]:443 ssl;{{end}}
	ssl_certificate {{ makeSecretPath "/etc/nginx/secrets/spiffe_cert.pem" $.StaticSSLPath "$secret_dir_path" $.DynamicSSLReloadEnabled }};
	ssl_certificate_key {{ makeSecretPath "/etc/nginx/secrets/spiffe_key.pem" $.StaticSSLPath "$secret_dir_path" $.DynamicSSLReloadEnabled }};
	{{- else}}
	{{- if not $server.GRPCOnly}}
	{{- range $port := $server.Ports}}
	listen {{$port}}{{if $server.ProxyProtocol}} proxy_protocol{{end}};
	{{- if not $server.DisableIPV6}}listen [::]:{{$port}}{{if $server.ProxyProtocol}} proxy_protocol{{end}};{{end}}
	{{- end}}
	{{- end}}

	{{- if $server.SSL}}
	{{- if $server.TLSPassthrough}}
	listen unix:/var/lib/nginx/passthrough-https.sock ssl proxy_protocol;
	set_real_ip_from unix:;
	real_ip_header proxy_protocol;
	{{- else}}
	{{- range $port := $server.SSLPorts}}
	listen {{$port}} ssl{{if $server.ProxyProtocol}} proxy_protocol{{end}};
	{{- if not $server.DisableIPV6}}listen [::]:{{$port}} ssl{{if $server.ProxyProtocol}} proxy_protocol{{end}};{{end}}
	{{- end}}
	{{- end}}
	{{- if $server.HTTP2}}
	http2 on;
	{{- end}}
	{{- if $server.SSLRejectHandshake}}
	ssl_reject_handshake on;
	{{- else}}
	ssl_certificate {{ makeSecretPath $server.SSLCertificate $.StaticSSLPath "$secret_dir_path" $.DynamicSSLReloadEnabled }};
	ssl_certificate_key {{ makeSecretPath $server.SSLCertificateKey $.StaticSSLPath "$secret_dir_path" $.DynamicSSLReloadEnabled }};
	{{- end}}
	{{- end}}
	{{- end}}

	{{- range $setRealIPFrom := $server.SetRealIPFrom}}
	set_real_ip_from {{$setRealIPFrom}};{{end}}
	{{- if $server.RealIPHeader}}real_ip_header {{$server.RealIPHeader}};{{end}}
	{{- if $server.RealIPRecursive}}real_ip_recursive on;{{end}}

	server_tokens {{$server.ServerTokens}};

	server_name {{$server.Name}};

	set $resource_type "ingress";
	set $resource_name "{{$.Ingress.Name}}";
	set $resource_namespace "{{$.Ingress.Namespace}}";

	{{- range $proxyHideHeader := $server.ProxyHideHeaders}}
	proxy_hide_header {{$proxyHideHeader}};{{end}}
	{{- range $proxyPassHeader := $server.ProxyPassHeaders}}
	proxy_pass_header {{$proxyPassHeader}};{{end}}

	{{- if and $server.HSTS (or $server.SSL $server.HSTSBehindProxy)}}
	set $hsts_header_val "";
	proxy_hide_header Strict-Transport-Security;
	{{- if $server.HSTSBehindProxy}}
	if ($http_x_forwarded_proto = 'https') {
	{{- else}}
	if ($https = on) {
	{{- end}}
		set $hsts_header_val "max-age={{$server.HSTSMaxAge}}; {{if $server.HSTSIncludeSubdomains}}includeSubDomains; {{end}}preload";
	}

	add_header Strict-Transport-Security "$hsts_header_val" always;
	{{- end}}

	{{- if $server.SSL}}
	{{- if not $server.GRPCOnly}}
	{{- if $server.SSLRedirect}}
	if ($scheme = http) {
		return 301 https://$host:{{index $server.SSLPorts 0}}$request_uri;
	}
	{{- end}}
	{{- end}}
	{{- end}}

	{{- if $server.RedirectToHTTPS}}
	if ($http_x_forwarded_proto = 'http') {
		return 301 https://$host$request_uri;
	}
	{{- end}}

	{{- with $server.BasicAuth }}
	auth_basic {{ printf "%q" .Realm }};
	auth_basic_user_file {{ .Secret }};
	{{- end }}

	{{- if $server.ServerSnippets}}
	{{- range $value := $server.ServerSnippets}}
	{{$value}}{{end}}
	{{- end}}

	{{- range $location := $server.Locations}}
	location {{  makeLocationPath $location $.Ingress.Annotations | printf }} {
		set $service "{{$location.ServiceName}}";
		{{- with $location.MinionIngress}}
		# location for minion {{$location.MinionIngress.Namespace}}/{{$location.MinionIngress.Name}}
		set $resource_name "{{$location.MinionIngress.Name}}";
		set $resource_namespace "{{$location.MinionIngress.Namespace}}";
		{{- end}}
		{{- if $location.GRPC}}
		{{- if not $server.GRPCOnly}}
		error_page 400 @grpcerror400;
		error_page 401 @grpcerror401;
		error_page 403 @grpcerror403;
		error_page 404 @grpcerror404;
		error_page 405 @grpcerror405;
		error_page 408 @grpcerror408;
		error_page 414 @grpcerror414;
		error_page 426 @grpcerror426;
		error_page 500 @grpcerror500;
		error_page 501 @grpcerror501;
		error_page 502 @grpcerror502;
		error_page 503 @grpcerror503;
		error_page 504 @grpcerror504;
		{{- end}}

		{{- if $location.LocationSnippets}}
		{{- range $value := $location.LocationSnippets}}
		{{$value}}{{end}}
		{{- end}}

		{{- with $location.BasicAuth }}
		auth_basic {{ printf "%q" .Realm }};
		auth_basic_user_file {{ .Secret }};
		{{- end }}

		grpc_connect_timeout {{$location.ProxyConnectTimeout}};
		grpc_read_timeout {{$location.ProxyReadTimeout}};
		grpc_send_timeout {{$location.ProxySendTimeout}};
		grpc_set_header Host $host;
		grpc_set_header X-Real-IP $remote_addr;
		grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		grpc_set_header X-Forwarded-Host $host;
		grpc_set_header X-Forwarded-Port $server_port;
		grpc_set_header X-Forwarded-Proto {{if $server.RedirectToHTTPS}}https{{else}}$scheme{{end}};

		{{- if $location.ProxyBufferSize}}
		grpc_buffer_size {{$location.ProxyBufferSize}};
		{{- end}}
		{{- if $.SpiffeClientCerts}}
		grpc_ssl_certificate {{ makeSecretPath "/etc/nginx/secrets/spiffe_cert.pem" $.StaticSSLPath "$secret_dir_path" $.DynamicSSLReloadEnabled }};
		grpc_ssl_certificate_key {{ makeSecretPath "/etc/nginx/secrets/spiffe_key.pem" $.StaticSSLPath "$secret_dir_path" $.DynamicSSLReloadEnabled }};
		grpc_ssl_trusted_certificate /etc/nginx/secrets/spiffe_rootca.pem;
		grpc_ssl_server_name on;
		grpc_ssl_verify on;
		grpc_ssl_verify_depth 25;
		grpc_ssl_name {{$location.ProxySSLName}};
		{{- end}}
		{{- if $location.SSL}}
		grpc_pass grpcs://{{$location.Upstream.Name}}{{$location.Rewrite}};
		{{- else}}
		grpc_pass grpc://{{$location.Upstream.Name}}{{$location.Rewrite}};
		{{- end}}
		{{- else}}
		proxy_http_version 1.1;
		{{- if $location.Websocket}}
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection $connection_upgrade;
		{{- else}}
		{{- if $.Keepalive}}
		proxy_set_header Connection "";{{end}}
		{{- end}}
		{{- if $location.LocationSnippets}}
		{{range $value := $location.LocationSnippets}}
		{{$value}}{{end}}
		{{- end}}
		{{- with $location.BasicAuth }}
		auth_basic {{ printf "%q" .Realm }};
		auth_basic_user_file {{ .Secret }};
		{{- end }}
		proxy_connect_timeout {{$location.ProxyConnectTimeout}};
		proxy_read_timeout {{$location.ProxyReadTimeout}};
		proxy_send_timeout {{$location.ProxySendTimeout}};
		client_max_body_size {{$location.ClientMaxBodySize}};
		{{- $proxySetHeaders := generateProxySetHeaders $location $.Ingress.Annotations -}}
		{{$proxySetHeaders}}
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Host $host;
		proxy_set_header X-Forwarded-Port $server_port;
		proxy_set_header X-Forwarded-Proto {{if $server.RedirectToHTTPS}}https{{else}}$scheme{{end}};
		proxy_buffering {{if $location.ProxyBuffering}}on{{else}}off{{end}};

		{{- if $location.ProxyBuffers}}
		proxy_buffers {{$location.ProxyBuffers}};
		{{- end}}
		{{- if $location.ProxyBufferSize}}
		proxy_buffer_size {{$location.ProxyBufferSize}};
		{{- end}}
		{{- if $location.ProxyMaxTempFileSize}}
		proxy_max_temp_file_size {{$location.ProxyMaxTempFileSize}};
		{{- end}}
		{{- if $.SpiffeClientCerts}}
		proxy_ssl_certificate {{ makeSecretPath "/etc/nginx/secrets/spiffe_cert.pem" $.StaticSSLPath "$secret_dir_path" $.DynamicSSLReloadEnabled }};
		proxy_ssl_certificate_key {{ makeSecretPath "/etc/nginx/secrets/spiffe_key.pem" $.StaticSSLPath "$secret_dir_path" $.DynamicSSLReloadEnabled }};
		proxy_ssl_trusted_certificate /etc/nginx/secrets/spiffe_rootca.pem;
		proxy_ssl_server_name on;
		proxy_ssl_verify on;
		proxy_ssl_verify_depth 25;
		proxy_ssl_name {{$location.ProxySSLName}};
		{{- end}}
		{{- if $location.SSL}}
		proxy_pass https://{{$location.Upstream.Name}}{{$location.Rewrite}};
		{{- else}}
		proxy_pass http://{{$location.Upstream.Name}}{{$location.Rewrite}};
		{{- end}}
		{{- end}}

		{{with $location.LimitReq}}
		limit_req zone={{ $location.LimitReq.Zone }} {{if $location.LimitReq.Burst}}burst={{$location.LimitReq.Burst}}{{end}} {{if $location.LimitReq.NoDelay}}nodelay{{else if $location.LimitReq.Delay}}delay={{$location.LimitReq.Delay}}{{end}};
		{{if $location.LimitReq.DryRun}}limit_req_dry_run on;{{end}}
		{{if $location.LimitReq.LogLevel}}limit_req_log_level {{$location.LimitReq.LogLevel}};{{end}}
		{{if $location.LimitReq.RejectCode}}limit_req_status {{$location.LimitReq.RejectCode}};{{end}}
		{{end}}
	}
	{{end -}}
	{{- if $server.GRPCOnly}}
	error_page 400 @grpcerror400;
	error_page 401 @grpcerror401;
	error_page 403 @grpcerror403;
	error_page 404 @grpcerror404;
	error_page 405 @grpcerror405;
	error_page 408 @grpcerror408;
	error_page 414 @grpcerror414;
	error_page 426 @grpcerror426;
	error_page 500 @grpcerror500;
	error_page 501 @grpcerror501;
	error_page 502 @grpcerror502;
	error_page 503 @grpcerror503;
	error_page 504 @grpcerror504;
	{{- end}}
	{{- if $server.HTTP2}}
	location @grpcerror400 { default_type application/grpc; return 400 "\n"; }
	location @grpcerror401 { default_type application/grpc; return 401 "\n"; }
	location @grpcerror403 { default_type application/grpc; return 403 "\n"; }
	location @grpcerror404 { default_type application/grpc; return 404 "\n"; }
	location @grpcerror405 { default_type application/grpc; return 405 "\n"; }
	location @grpcerror408 { default_type application/grpc; return 408 "\n"; }
	location @grpcerror414 { default_type application/grpc; return 414 "\n"; }
	location @grpcerror426 { default_type application/grpc; return 426 "\n"; }
	location @grpcerror500 { default_type application/grpc; return 500 "\n"; }
	location @grpcerror501 { default_type application/grpc; return 501 "\n"; }
	location @grpcerror502 { default_type application/grpc; return 502 "\n"; }
	location @grpcerror503 { default_type application/grpc; return 503 "\n"; }
	location @grpcerror504 { default_type application/grpc; return 504 "\n"; }
	{{- end}}
}{{end}}
`
