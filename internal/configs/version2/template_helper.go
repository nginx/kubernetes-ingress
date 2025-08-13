package version2

import (
	"fmt"
	"strconv"
	"strings"
	"text/template"

	"github.com/nginx/kubernetes-ingress/internal/configs/commonhelpers"
)

type protocol int

const (
	http protocol = iota
	https
)

type ipType int

const (
	ipv4 ipType = iota
	ipv6
)

type listen struct {
	ipAddress     string
	port          string
	tls           bool
	proxyProtocol bool
	udp           bool
	ipType        ipType
}

const spacing = "    "

func headerListToCIMap(headers []Header) map[string]string {
	ret := make(map[string]string)

	for _, header := range headers {
		ret[strings.ToLower(header.Name)] = header.Value
	}

	return ret
}

func hasCIKey(key string, d map[string]string) bool {
	_, ok := d[strings.ToLower(key)]
	return ok
}

func makeListener(listenerType protocol, s Server) string {
	var directives string

	if !s.CustomListeners {
		directives += buildDefaultListenerDirectives(listenerType, s)
	} else {
		directives += buildCustomListenerDirectives(listenerType, s)
	}

	return directives
}

func buildDefaultListenerDirectives(listenerType protocol, s Server) string {
	port := getDefaultPort(listenerType)
	return buildListenerDirectives(listenerType, s, port)
}

func buildCustomListenerDirectives(listenerType protocol, s Server) string {
	if (listenerType == http && s.HTTPPort > 0) || (listenerType == https && s.HTTPSPort > 0) {
		port := getCustomPort(listenerType, s)
		return buildListenerDirectives(listenerType, s, port)
	}
	return ""
}

func buildListenerDirectives(listenerType protocol, s Server, port string) string {
	var directives string

	if listenerType == http {
		directives += buildListenDirective(listen{
			ipAddress:     s.HTTPIPv4,
			port:          port,
			tls:           false,
			proxyProtocol: s.ProxyProtocol,
			udp:           false,
			ipType:        ipv4,
		})
		if !s.DisableIPV6 {
			directives += spacing
			directives += buildListenDirective(listen{
				ipAddress:     s.HTTPIPv6,
				port:          port,
				tls:           false,
				proxyProtocol: s.ProxyProtocol,
				udp:           false,
				ipType:        ipv6,
			})
		}
	} else {
		directives += buildListenDirective(listen{
			ipAddress:     s.HTTPSIPv4,
			port:          port,
			tls:           true,
			proxyProtocol: s.ProxyProtocol,
			udp:           false,
			ipType:        ipv4,
		})
		if !s.DisableIPV6 {
			directives += spacing
			directives += buildListenDirective(listen{
				ipAddress:     s.HTTPSIPv6,
				port:          port,
				tls:           true,
				proxyProtocol: s.ProxyProtocol,
				udp:           false,
				ipType:        ipv6,
			})
		}
	}

	return directives
}

func getDefaultPort(listenerType protocol) string {
	s := Server{
		HTTPPort:  80,
		HTTPSPort: 443,
	}

	return getCustomPort(listenerType, s)
}

func getCustomPort(listenerType protocol, s Server) string {
	if listenerType == http {
		return strconv.Itoa(s.HTTPPort)
	}
	return strconv.Itoa(s.HTTPSPort)
}

func buildListenDirective(l listen) string {
	base := "listen"
	var directive string

	if l.ipType == ipv6 {
		if l.ipAddress == "" {
			l.ipAddress = "::"
		}
		l.ipAddress = fmt.Sprintf("[%s]", l.ipAddress)
	}

	if l.ipAddress != "" {
		directive = fmt.Sprintf("%s %s:%s", base, l.ipAddress, l.port)
	} else {
		directive = fmt.Sprintf("%s %s", base, l.port)
	}

	if l.tls {
		directive += " ssl"
	}

	if l.proxyProtocol {
		directive += " proxy_protocol"
	}

	if l.udp {
		directive += " udp"
	}

	directive += ";\n"
	return directive
}

func makeHTTPListener(s Server) string {
	return makeListener(http, s)
}

func makeHTTPSListener(s Server) string {
	return makeListener(https, s)
}

func makeTransportListener(s StreamServer) string {
	var directives string
	port := strconv.Itoa(s.Port)

	directives += buildListenDirective(listen{
		ipAddress:     s.IPv4,
		port:          port,
		tls:           s.SSL.Enabled,
		proxyProtocol: false,
		udp:           s.UDP,
		ipType:        ipv4,
	})

	if !s.DisableIPV6 {
		directives += spacing
		directives += buildListenDirective(listen{
			ipAddress:     s.IPv6,
			port:          port,
			tls:           s.SSL.Enabled,
			proxyProtocol: false,
			udp:           s.UDP,
			ipType:        ipv6,
		})
	}

	return directives
}

func makeHeaderQueryValue(apiKey APIKey) string {
	var parts []string

	for _, header := range apiKey.Header {
		nginxHeader := strings.ReplaceAll(header, "-", "_")
		nginxHeader = strings.ToLower(nginxHeader)

		parts = append(parts, fmt.Sprintf("${http_%s}", nginxHeader))
	}

	for _, query := range apiKey.Query {
		parts = append(parts, fmt.Sprintf("${arg_%s}", query))
	}

	return fmt.Sprintf("\"%s\"", strings.Join(parts, ""))
}

func makeServerName(s StreamServer) string {
	if s.TLSPassthrough || s.ServerName == "" || s.SSL == nil {
		return ""
	}
	return fmt.Sprintf("server_name \"%s\";", s.ServerName)
}

// boolToInteger will do the following conversions:
// false -> 0
// true -> 1
//
// An example for where it's used is the OIDC PKCE Enable flag.
func boolToInteger(b bool) int {
	// The compiler currently only optimizes this form.
	// See issue 6011.
	var i int
	if b {
		i = 1
	} else {
		i = 0
	}
	return i
}

var helperFunctions = template.FuncMap{
	"headerListToCIMap":     headerListToCIMap,
	"hasCIKey":              hasCIKey,
	"contains":              strings.Contains,
	"hasPrefix":             strings.HasPrefix,
	"hasSuffix":             strings.HasSuffix,
	"toLower":               strings.ToLower,
	"toUpper":               strings.ToUpper,
	"replaceAll":            strings.ReplaceAll,
	"makeHTTPListener":      makeHTTPListener,
	"makeHTTPSListener":     makeHTTPSListener,
	"makeSecretPath":        commonhelpers.MakeSecretPath,
	"makeHeaderQueryValue":  makeHeaderQueryValue,
	"makeTransportListener": makeTransportListener,
	"makeServerName":        makeServerName,
	"boolToInteger":         boolToInteger,
}
