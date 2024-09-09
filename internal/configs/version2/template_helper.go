package version2

import (
	"fmt"
	"strconv"
	"strings"
	"text/template"

	"github.com/nginxinc/kubernetes-ingress/internal/configs/commonhelpers"
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
		directives += buildListenDirective(s.HTTPIPv4, port, false, s.ProxyProtocol, false, ipv4)
		if !s.DisableIPV6 {
			directives += spacing
			directives += buildListenDirective(s.HTTPIPv6, port, false, s.ProxyProtocol, false, ipv6)
		}
	} else {
		directives += buildListenDirective(s.HTTPSIPv4, port, false, s.ProxyProtocol, false, ipv4)
		if !s.DisableIPV6 {
			directives += spacing
			directives += buildListenDirective(s.HTTPSIPv6, port, false, s.ProxyProtocol, false, ipv6)
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
	return strconv.Itoa(s.HTTPSPort) + " ssl"
}

func buildListenDirective(ip string, port string, tls bool, proxyProtocol bool, udp bool, ipType ipType) string {
	base := "listen"
	var directive string

	if ipType == ipv6 {
		if ip != "" {
			directive = fmt.Sprintf("%s [%s]:%s", base, ip, port)
		} else {
			directive = fmt.Sprintf("%s [::]:%s", base, port)
		}
	} else {
		if ip != "" {
			directive = fmt.Sprintf("%s %s:%s", base, ip, port)
		} else {
			directive = fmt.Sprintf("%s %s", base, port)
		}
	}

	if tls {
		directive += " ssl"
	}

	if proxyProtocol {
		directive += " proxy_protocol"
	}

	if udp {
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

	directives += buildListenDirective("", port, s.SSL.Enabled, false, s.UDP, ipv4)

	if !s.DisableIPV6 {
		directives += spacing
		directives += buildListenDirective("", port, s.SSL.Enabled, false, s.UDP, ipv6)
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
}
