package validation

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// TransportServerValidator validates a TransportServer resource.
type TransportServerValidator struct {
	tlsPassthrough  bool
	snippetsEnabled bool
	isPlus          bool
}

// NewTransportServerValidator creates a new TransportServerValidator.
func NewTransportServerValidator(tlsPassthrough bool, snippetsEnabled bool, isPlus bool) *TransportServerValidator {
	return &TransportServerValidator{
		tlsPassthrough:  tlsPassthrough,
		snippetsEnabled: snippetsEnabled,
		isPlus:          isPlus,
	}
}

// ValidateTransportServer validates a TransportServer.
func (tsv *TransportServerValidator) ValidateTransportServer(transportServer *conf_v1.TransportServer) error {
	allErrs := tsv.validateTransportServerSpec(&transportServer.Spec, field.NewPath("spec"))
	return allErrs.ToAggregate()
}

func (tsv *TransportServerValidator) validateTransportServerSpec(spec *conf_v1.TransportServerSpec, fieldPath *field.Path) field.ErrorList {
	allErrs := tsv.validateTransportListener(&spec.Listener, fieldPath.Child("listener"))

	isTLSPassthroughListener := isPotentialTLSPassthroughListener(&spec.Listener)
	allErrs = append(allErrs, validateTransportServerHost(spec.Host, fieldPath.Child("host"), isTLSPassthroughListener, spec.Listener.Protocol, spec.TLS)...)

	upstreamErrs, upstreamNames := validateTransportServerUpstreams(spec.Upstreams, fieldPath.Child("upstreams"), tsv.isPlus)
	allErrs = append(allErrs, upstreamErrs...)

	allErrs = append(allErrs, validateTransportServerUpstreamParameters(spec.UpstreamParameters, fieldPath.Child("upstreamParameters"), spec.Listener.Protocol)...)

	allErrs = append(allErrs, validateSessionParameters(spec.SessionParameters, fieldPath.Child("sessionParameters"))...)

	if spec.Action == nil {
		allErrs = append(allErrs, field.Required(fieldPath.Child("action"), "must specify action"))
	} else {
		allErrs = append(allErrs, validateTransportServerAction(spec.Action, fieldPath.Child("action"), upstreamNames)...)
	}

	allErrs = append(allErrs, validateSnippets(spec.ServerSnippets, fieldPath.Child("serverSnippets"), tsv.snippetsEnabled)...)

	allErrs = append(allErrs, validateSnippets(spec.StreamSnippets, fieldPath.Child("streamSnippets"), tsv.snippetsEnabled)...)

	hostSpecified := spec.Host != ""
	allErrs = append(allErrs, validateTLS(spec.TLS, isTLSPassthroughListener, fieldPath.Child("tls"), hostSpecified)...)

	return allErrs
}

func validateTLS(
	tls *conf_v1.TransportServerTLS,
	isTLSPassthroughListener bool,
	fieldPath *field.Path,
	hostSpecified bool,
) field.ErrorList {
	if isTLSPassthroughListener {
		if tls != nil {
			return field.ErrorList{field.Forbidden(fieldPath, "cannot specify tls for TLS Passthrough TransportServers")}
		}
		return nil
	}

	if hostSpecified {
		if tls == nil || tls.Secret == "" {
			return field.ErrorList{field.Required(fieldPath, "must specify spec.tls.secret when host is specified, and the TransportServer is not using the TLS Passthrough listener")}
		}
		return validateSecretName(tls.Secret, fieldPath.Child("secret"))
	}

	if tls != nil && tls.Secret != "" {
		return validateSecretName(tls.Secret, fieldPath.Child("secret"))
	}

	return nil
}

func validateSnippets(serverSnippet string, fieldPath *field.Path, snippetsEnabled bool) field.ErrorList {
	if !snippetsEnabled && serverSnippet != "" {
		return field.ErrorList{field.Forbidden(fieldPath, "snippet specified but snippets feature is not enabled")}
	}
	return nil
}

func validateTransportServerHost(host string, fieldPath *field.Path, isTLSPassthroughListener bool, protocol string, tls *conf_v1.TransportServerTLS) field.ErrorList {
	if protocol == "UDP" {
		if host != "" {
			return field.ErrorList{field.Forbidden(fieldPath, "host field is not allowed for UDP TransportServers")}
		}
		return nil
	}

	if host != "" {
		if !isTLSPassthroughListener {
			if tls == nil || tls.Secret == "" {
				return field.ErrorList{field.Required(fieldPath, "must specify spec.tls.secret when host is specified for non-TLS Passthrough TransportServers")}
			}
			return validateHost(host, fieldPath)
		}
		if tls != nil && tls.Secret != "" {
			return field.ErrorList{field.Required(fieldPath, "must not specify spec.tls.secret when host using TLS Passthrough")}
		}
		return validateHost(host, fieldPath)
	}

	if isTLSPassthroughListener {
		return field.ErrorList{field.Required(fieldPath, "must specify host for TLS Passthrough TransportServers")}
	}

	return nil
}

func (tsv *TransportServerValidator) validateTransportListener(listener *conf_v1.TransportServerListener, fieldPath *field.Path) field.ErrorList {
	if isPotentialTLSPassthroughListener(listener) {
		return tsv.validateTLSPassthroughListener(listener, fieldPath)
	}

	return validateRegularListener(listener, fieldPath)
}

func validateRegularListener(listener *conf_v1.TransportServerListener, fieldPath *field.Path) field.ErrorList {
	allErrs := validateListenerName(listener.Name, fieldPath.Child("name"))
	allErrs = append(allErrs, validateListenerProtocol(listener.Protocol, fieldPath.Child("protocol"))...)
	return allErrs
}

func isPotentialTLSPassthroughListener(listener *conf_v1.TransportServerListener) bool {
	return listener.Name == conf_v1.TLSPassthroughListenerName || listener.Protocol == conf_v1.TLSPassthroughListenerProtocol
}

func (tsv *TransportServerValidator) validateTLSPassthroughListener(listener *conf_v1.TransportServerListener, fieldPath *field.Path) field.ErrorList {
	if !tsv.tlsPassthrough {
		return field.ErrorList{field.Forbidden(fieldPath, "TLS Passthrough is not enabled")}
	}
	if listener.Name == conf_v1.TLSPassthroughListenerName && listener.Protocol != conf_v1.TLSPassthroughListenerProtocol {
		msg := fmt.Sprintf("must be '%s' for the built-in %s listener", conf_v1.TLSPassthroughListenerProtocol, conf_v1.TLSPassthroughListenerName)
		return field.ErrorList{field.Invalid(fieldPath.Child("protocol"), listener.Protocol, msg)}
	}
	if listener.Protocol == conf_v1.TLSPassthroughListenerProtocol && listener.Name != conf_v1.TLSPassthroughListenerName {
		msg := fmt.Sprintf("must be '%s' for a listener with the protocol %s", conf_v1.TLSPassthroughListenerName, conf_v1.TLSPassthroughListenerProtocol)
		return field.ErrorList{field.Invalid(fieldPath.Child("name"), listener.Name, msg)}
	}
	return nil
}

func validateListenerName(name string, fieldPath *field.Path) field.ErrorList {
	return validateDNS1035Label(name, fieldPath)
}

func validateTransportServerUpstreams(upstreams []conf_v1.TransportServerUpstream, fieldPath *field.Path, isPlus bool) (allErrs field.ErrorList, upstreamNames sets.Set[string]) {
	allErrs = field.ErrorList{}
	upstreamNames = sets.Set[string]{}

	for i, u := range upstreams {
		idxPath := fieldPath.Index(i)

		upstreamErrors := validateUpstreamName(u.Name, idxPath.Child("name"))
		if len(upstreamErrors) > 0 {
			allErrs = append(allErrs, upstreamErrors...)
		} else if upstreamNames.Has(u.Name) {
			allErrs = append(allErrs, field.Duplicate(idxPath.Child("name"), u.Name))
		} else {
			upstreamNames.Insert(u.Name)
		}

		allErrs = append(allErrs, validateServiceName(u.Service, idxPath.Child("service"))...)
		allErrs = append(allErrs, validatePositiveIntOrZeroFromPointer(u.MaxFails, idxPath.Child("maxFails"))...)
		allErrs = append(allErrs, validatePositiveIntOrZeroFromPointer(u.MaxFails, idxPath.Child("maxConns"))...)
		allErrs = append(allErrs, validateTime(u.FailTimeout, idxPath.Child("failTimeout"))...)

		for _, msg := range validation.IsValidPortNum(u.Port) {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("port"), u.Port, msg))
		}

		allErrs = append(allErrs, validateTSUpstreamHealthChecks(u.HealthCheck, idxPath.Child("healthChecks"))...)
		allErrs = append(allErrs, validateLoadBalancingMethod(u.LoadBalancingMethod, idxPath.Child("loadBalancingMethod"), isPlus)...)
		allErrs = append(allErrs, validateBackup(u.Backup, u.BackupPort, u.LoadBalancingMethod, idxPath)...)
	}

	return allErrs, upstreamNames
}

func validateLoadBalancingMethod(method string, fieldPath *field.Path, isPlus bool) field.ErrorList {
	if method == "" {
		return nil
	}

	method = strings.TrimSpace(method)
	if strings.HasPrefix(method, "hash") {
		return validateHashLoadBalancingMethod(method, fieldPath, isPlus)
	}

	validMethodValues := nginxStreamLoadBalanceValidInput
	if isPlus {
		validMethodValues = nginxPlusStreamLoadBalanceValidInput
	}
	if _, exists := validMethodValues[method]; !exists {
		return field.ErrorList{field.Invalid(fieldPath, method, fmt.Sprintf("load balancing method is not valid: %v", method))}
	}
	return nil
}

var nginxStreamLoadBalanceValidInput = map[string]bool{
	"round_robin":           true,
	"least_conn":            true,
	"random":                true,
	"random two":            true,
	"random two least_conn": true,
}

var nginxPlusStreamLoadBalanceValidInput = map[string]bool{
	"round_robin":                   true,
	"least_conn":                    true,
	"random":                        true,
	"random two":                    true,
	"random two least_conn":         true,
	"random least_conn":             true,
	"least_time connect":            true,
	"least_time first_byte":         true,
	"least_time last_byte":          true,
	"least_time last_byte inflight": true,
}

var loadBalancingVariables = map[string]bool{
	"remote_addr": true,
}

var hashMethodRegexp = regexp.MustCompile(`^hash (\S+)(?: consistent)?$`)

func validateHashLoadBalancingMethod(method string, fieldPath *field.Path, isPlus bool) field.ErrorList {
	matches := hashMethodRegexp.FindStringSubmatch(method)
	if len(matches) != 2 {
		msg := fmt.Sprintf("invalid value for load balancing method: %v", method)
		return field.ErrorList{field.Invalid(fieldPath, method, msg)}
	}

	allErrs := field.ErrorList{}
	hashKey := matches[1]
	if strings.Contains(hashKey, "$") {
		varErrs := validateStringWithVariables(hashKey, fieldPath, []string{}, loadBalancingVariables, isPlus)
		allErrs = append(allErrs, varErrs...)
	}
	if err := ValidateEscapedString(method); err != nil {
		msg := fmt.Sprintf("invalid value for hash: %v", err)
		return append(allErrs, field.Invalid(fieldPath, method, msg))
	}
	return allErrs
}

func validateTSUpstreamHealthChecks(hc *conf_v1.TransportServerHealthCheck, fieldPath *field.Path) field.ErrorList {
	if hc == nil {
		return nil
	}
	allErrs := validateTime(hc.Timeout, fieldPath.Child("timeout"))
	allErrs = append(allErrs, validateTime(hc.Interval, fieldPath.Child("interval"))...)
	allErrs = append(allErrs, validateTime(hc.Jitter, fieldPath.Child("jitter"))...)
	allErrs = append(allErrs, validatePositiveIntOrZero(hc.Fails, fieldPath.Child("fails"))...)
	allErrs = append(allErrs, validatePositiveIntOrZero(hc.Passes, fieldPath.Child("passes"))...)

	if hc.Port > 0 {
		for _, msg := range validation.IsValidPortNum(hc.Port) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("port"), hc.Port, msg))
		}
	}
	allErrs = append(allErrs, validateHealthCheckMatch(hc.Match, fieldPath.Child("match"))...)
	return allErrs
}

func validateHealthCheckMatch(match *conf_v1.TransportServerMatch, fieldPath *field.Path) field.ErrorList {
	if match == nil {
		return nil
	}

	allErrs := validateMatchExpect(match.Expect, fieldPath.Child("expect"))
	allErrs = append(allErrs, validateMatchSend(match.Expect, fieldPath.Child("send"))...)
	return allErrs
}

func validateMatchExpect(expect string, fieldPath *field.Path) field.ErrorList {
	if expect == "" {
		return nil
	}
	if err := ValidateEscapedString(expect); err != nil {
		return field.ErrorList{field.Invalid(fieldPath, expect, err.Error())}
	}

	if strings.HasPrefix(expect, "~") {
		var expr string
		if strings.HasPrefix(expect, "~*") {
			expr = strings.TrimPrefix(expect, "~*")
		} else {
			expr = strings.TrimPrefix(expect, "~")
		}

		// compile also validates hex literals
		if _, err := regexp.Compile(expr); err != nil {
			return field.ErrorList{field.Invalid(fieldPath, expr, fmt.Sprintf("must be a valid regular expression: %v", err))}
		}
	} else {
		if err := validateHexString(expect); err != nil {
			return field.ErrorList{field.Invalid(fieldPath, expect, err.Error())}
		}
	}

	return nil
}

func validateMatchSend(send string, fieldPath *field.Path) field.ErrorList {
	if send == "" {
		return nil
	}

	if err := ValidateEscapedString(send); err != nil {
		return field.ErrorList{field.Invalid(fieldPath, send, err.Error())}
	}

	if err := validateHexString(send); err != nil {
		return field.ErrorList{field.Invalid(fieldPath, send, err.Error())}
	}
	return nil
}

var hexLiteralRegexp = regexp.MustCompile(`\\x(.{0,2})`)

func validateHexString(s string) error {
	literals := hexLiteralRegexp.FindAllStringSubmatch(s, -1)
	for _, match := range literals {
		lit := match[0]
		digits := match[1]

		if len(digits) != 2 {
			return fmt.Errorf("hex literal '%s' must contain two hex digits", lit)
		}

		_, err := hex.DecodeString(digits)
		if err != nil {
			return fmt.Errorf("hex literal '%s' must contain two hex digits: %w", lit, err)
		}
	}

	return nil
}

func validateTransportServerUpstreamParameters(upstreamParameters *conf_v1.UpstreamParameters, fieldPath *field.Path, protocol string) field.ErrorList {
	if upstreamParameters == nil {
		return nil
	}

	allErrs := validateUDPUpstreamParameter(upstreamParameters.UDPRequests, fieldPath.Child("udpRequests"), protocol)
	allErrs = append(allErrs, validateUDPUpstreamParameter(upstreamParameters.UDPResponses, fieldPath.Child("udpResponses"), protocol)...)
	allErrs = append(allErrs, validateTime(upstreamParameters.ConnectTimeout, fieldPath.Child("connectTimeout"))...)
	allErrs = append(allErrs, validateTime(upstreamParameters.NextUpstreamTimeout, fieldPath.Child("nextUpstreamTimeout"))...)
	allErrs = append(allErrs, validatePositiveIntOrZero(upstreamParameters.NextUpstreamTries, fieldPath.Child("nextUpstreamTries"))...)
	return allErrs
}

func validateSessionParameters(sessionParameters *conf_v1.SessionParameters, fieldPath *field.Path) field.ErrorList {
	if sessionParameters == nil {
		return nil
	}
	return validateTime(sessionParameters.Timeout, fieldPath.Child("timeout"))
}

func validateUDPUpstreamParameter(parameter *int, fieldPath *field.Path, protocol string) field.ErrorList {
	if parameter != nil && protocol != "UDP" {
		return field.ErrorList{field.Forbidden(fieldPath, "is not allowed for non-UDP TransportServers")}
	}
	return validatePositiveIntOrZeroFromPointer(parameter, fieldPath)
}

func validateTransportServerAction(action *conf_v1.TransportServerAction, fieldPath *field.Path, upstreamNames sets.Set[string]) field.ErrorList {
	if action.Pass == "" {
		return field.ErrorList{field.Required(fieldPath, "must specify pass")}
	}
	return validateReferencedUpstream(action.Pass, fieldPath.Child("pass"), upstreamNames)
}
