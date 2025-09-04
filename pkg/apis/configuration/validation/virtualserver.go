package validation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/nginx/kubernetes-ingress/internal/configs"
	internalValidation "github.com/nginx/kubernetes-ingress/internal/validation"
	v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// VsvOption defines the signature of our VirtualServerValidator option functions.
type VsvOption func(*VirtualServerValidator)

// VirtualServerValidator validates a VirtualServer/VirtualServerRoute resource.
type VirtualServerValidator struct {
	isPlus                       bool
	isDosEnabled                 bool
	isCertManagerEnabled         bool
	isExternalDNSEnabled         bool
	isDirectiveAutoadjustEnabled bool
}

// IsPlus modifies the VirtualServerValidator to set the isPlus option.
func IsPlus(plus bool) VsvOption {
	return func(v *VirtualServerValidator) {
		v.isPlus = plus
	}
}

// IsDosEnabled modifies the VirtualServerValidator to set the isDosEnabled option.
func IsDosEnabled(dos bool) VsvOption {
	return func(v *VirtualServerValidator) {
		v.isDosEnabled = dos
	}
}

// IsCertManagerEnabled modifies the VirtualServerValidator to set the isCertManagerEnabled option.
func IsCertManagerEnabled(cm bool) VsvOption {
	return func(v *VirtualServerValidator) {
		v.isCertManagerEnabled = cm
	}
}

// IsExternalDNSEnabled modifies the VirtualServerValidator to set the isExternalDNSEnabled option.
func IsExternalDNSEnabled(ed bool) VsvOption {
	return func(v *VirtualServerValidator) {
		v.isExternalDNSEnabled = ed
	}
}

// IsDirectiveAutoadjustEnabled modifies the VirtualServerValidator to set the isDirectiveAutoadjustEnabled option.
func IsDirectiveAutoadjustEnabled(autoadjust bool) VsvOption {
	return func(v *VirtualServerValidator) {
		v.isDirectiveAutoadjustEnabled = autoadjust
	}
}

// NewVirtualServerValidator creates a new VirtualServerValidator.
func NewVirtualServerValidator(opts ...VsvOption) *VirtualServerValidator {
	vsv := VirtualServerValidator{
		isPlus:                       false,
		isDosEnabled:                 false,
		isCertManagerEnabled:         false,
		isExternalDNSEnabled:         false,
		isDirectiveAutoadjustEnabled: false,
	}
	for _, o := range opts {
		o(&vsv)
	}
	return &vsv
}

// ValidateVirtualServer validates a VirtualServer.
func (vsv *VirtualServerValidator) ValidateVirtualServer(virtualServer *v1.VirtualServer) error {
	allErrs := vsv.validateVirtualServerSpec(&virtualServer.Spec, field.NewPath("spec"), virtualServer.Namespace)
	return allErrs.ToAggregate()
}

// BalanceUpstreamProxies balances proxy buffer sizes for all upstreams in a VirtualServer.
func (vsv *VirtualServerValidator) BalanceUpstreamProxies(virtualServer *v1.VirtualServer) error {
	for i := range virtualServer.Spec.Upstreams {
		err := internalValidation.BalanceProxiesForUpstreams(&virtualServer.Spec.Upstreams[i], vsv.isDirectiveAutoadjustEnabled)
		if err != nil {
			return fmt.Errorf("upstream %d: %w", i, err)
		}
	}
	return nil
}

// BalanceUpstreamProxiesForRoute balances proxy buffer sizes for all upstreams in a VirtualServerRoute.
func (vsv *VirtualServerValidator) BalanceUpstreamProxiesForRoute(virtualServerRoute *v1.VirtualServerRoute) error {
	for i := range virtualServerRoute.Spec.Upstreams {
		err := internalValidation.BalanceProxiesForUpstreams(&virtualServerRoute.Spec.Upstreams[i], vsv.isDirectiveAutoadjustEnabled)
		if err != nil {
			return fmt.Errorf("upstream %d: %w", i, err)
		}
	}
	return nil
}

// validateVirtualServerSpec validates a VirtualServerSpec.
func (vsv *VirtualServerValidator) validateVirtualServerSpec(spec *v1.VirtualServerSpec, fieldPath *field.Path, namespace string) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateHost(spec.Host, fieldPath.Child("host"))...)
	allErrs = append(allErrs, vsv.validateTLS(spec.TLS, fieldPath.Child("tls"))...)
	allErrs = append(allErrs, validatePolicies(spec.Policies, fieldPath.Child("policies"), namespace)...)

	upstreamErrs, upstreamNames := vsv.validateUpstreams(spec.Upstreams, fieldPath.Child("upstreams"))
	allErrs = append(allErrs, upstreamErrs...)

	allErrs = append(allErrs, vsv.validateVirtualServerRoutes(spec.Routes, fieldPath.Child("routes"), upstreamNames, namespace)...)

	allErrs = append(allErrs, validateDos(vsv.isDosEnabled, spec.Dos, fieldPath.Child("dos"))...)

	allErrs = append(allErrs, vsv.validateExternalDNS(&spec.ExternalDNS, fieldPath.Child("externalDNS"))...)

	return allErrs
}

const wildcardPrefix = "*."

func validateHost(host string, fieldPath *field.Path) field.ErrorList {
	if host == "" {
		return field.ErrorList{field.Required(fieldPath, "")}
	}

	allErrs := field.ErrorList{}
	if strings.HasPrefix(host, wildcardPrefix) {
		for _, msg := range validation.IsWildcardDNS1123Subdomain(host) {
			allErrs = append(allErrs, field.Invalid(fieldPath, host, msg))
		}
	} else {
		for _, msg := range validation.IsDNS1123Subdomain(host) {
			allErrs = append(allErrs, field.Invalid(fieldPath, host, msg))
		}
	}

	return allErrs
}

func validatePolicies(policies []v1.PolicyReference, fieldPath *field.Path, namespace string) field.ErrorList {
	allErrs := field.ErrorList{}
	policyKeys := sets.Set[string]{}

	for i, p := range policies {
		idxPath := fieldPath.Index(i)

		polNamespace := p.Namespace
		if polNamespace == "" {
			polNamespace = namespace
		}

		key := fmt.Sprintf("%s/%s", polNamespace, p.Name)

		if policyKeys.Has(key) {
			allErrs = append(allErrs, field.Duplicate(idxPath, key))
		} else {
			policyKeys.Insert(key)
		}

		if p.Name == "" {
			allErrs = append(allErrs, field.Required(idxPath.Child("name"), ""))
		} else {
			for _, msg := range validation.IsDNS1123Subdomain(p.Name) {
				allErrs = append(allErrs, field.Invalid(idxPath.Child("name"), p.Name, msg))
			}
		}

		if p.Namespace != "" {
			for _, msg := range validation.IsDNS1123Label(p.Namespace) {
				allErrs = append(allErrs, field.Invalid(idxPath.Child("namespace"), p.Namespace, msg))
			}
		}
	}

	return allErrs
}

func (vsv *VirtualServerValidator) validateTLS(tls *v1.TLS, fieldPath *field.Path) field.ErrorList {
	if tls == nil {
		// valid case - tls is not defined
		return nil
	}

	allErrs := validateSecretName(tls.Secret, fieldPath.Child("secret"))
	allErrs = append(allErrs, validateTLSRedirect(tls.Redirect, fieldPath.Child("redirect"))...)
	allErrs = append(allErrs, validateTLSCmFields(tls.CertManager, vsv.isCertManagerEnabled, tls.Secret, fieldPath.Child("cert-manager"))...)
	return allErrs
}

func validateTLSCmFields(cm *v1.CertManager, isCertManagerEnabled bool, secret string, fieldPath *field.Path) field.ErrorList {
	if cm == nil {
		// valid, cert-manager is not required
		return nil
	}

	allErrs := field.ErrorList{}
	if !isCertManagerEnabled {
		allErrs = append(allErrs, field.Forbidden(fieldPath, "field requires cert-manager enablement"))
	}
	if secret == "" {
		// invalid, secret name is required for cert-manager configuration
		allErrs = append(allErrs, field.Forbidden(fieldPath, "field requires TLS.Secret to be specified"))
	}
	return allErrs
}

func validateDos(isDosEnabled bool, dos string, fieldPath *field.Path) field.ErrorList {
	if dos == "" {
		// valid, dos is not required
		return nil
	}

	allErrs := field.ErrorList{}
	if !isDosEnabled {
		allErrs = append(allErrs, field.Forbidden(fieldPath, "field requires DOS enablement"))
	}
	for _, msg := range validation.IsQualifiedName(dos) {
		allErrs = append(allErrs, field.Invalid(fieldPath, dos, msg))
	}
	return allErrs
}

func (vsv *VirtualServerValidator) validateExternalDNS(ed *v1.ExternalDNS, fieldPath *field.Path) field.ErrorList {
	if ed == nil || !ed.Enable {
		// valid, externalDNS is not required
		return nil
	}
	if !vsv.isExternalDNSEnabled {
		return field.ErrorList{field.Forbidden(fieldPath, "field requires externalDNS enablement")}
	}
	return nil
}

func validateTLSRedirect(redirect *v1.TLSRedirect, fieldPath *field.Path) field.ErrorList {
	if redirect == nil {
		return nil
	}

	allErrs := field.ErrorList{}
	if redirect.Code != nil {
		allErrs = append(allErrs, validateRedirectStatusCode(*redirect.Code, fieldPath.Child("code"))...)
	}

	if redirect.BasedOn != "" && redirect.BasedOn != "scheme" && redirect.BasedOn != "x-forwarded-proto" {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("basedOn"), redirect.BasedOn, "accepted values are 'scheme', 'x-forwarded-proto'"))
	}
	return allErrs
}

var validRedirectStatusCodes = map[int]bool{
	301: true,
	302: true,
	307: true,
	308: true,
}

func validateRedirectStatusCode(code int, fieldPath *field.Path) field.ErrorList {
	if _, ok := validRedirectStatusCodes[code]; !ok {
		return field.ErrorList{field.Invalid(fieldPath, code, "status code out of accepted range. accepted values are '301', '302', '307', '308'")}
	}
	return nil
}

func validatePositiveIntOrZero(n int, fieldPath *field.Path) field.ErrorList {
	if n < 0 {
		return field.ErrorList{field.Invalid(fieldPath, n, "must be positive")}
	}
	return nil
}

func validatePositiveIntOrZeroFromPointer(n *int, fieldPath *field.Path) field.ErrorList {
	if n == nil {
		return nil
	}
	if *n < 0 {
		return field.ErrorList{field.Invalid(fieldPath, n, "must be positive or zero")}
	}
	return nil
}

func validateBackupName(backup string, fieldPath *field.Path) field.ErrorList {
	if backup == "" {
		return nil
	}
	backupName := backup
	return validateServiceName(backupName, fieldPath.Child("backup"))
}

func validateBackupPortFromPointer(backupPort *uint16, fieldPath *field.Path) field.ErrorList {
	if backupPort == nil {
		return nil
	}
	port := *backupPort
	allErrs := field.ErrorList{}
	for _, msg := range validation.IsValidPortNum(int(port)) {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("port"), port, msg))
	}
	return allErrs
}

func validateBuffer(buff *v1.UpstreamBuffers, fieldPath *field.Path) field.ErrorList {
	if buff == nil {
		return nil
	}

	allErrs := field.ErrorList{}
	if buff.Number <= 0 {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("number"), buff.Number, "must be positive"))
	}

	if buff.Size == "" {
		allErrs = append(allErrs, field.Required(fieldPath.Child("size"), "cannot be empty"))
	} else {
		allErrs = append(allErrs, validateSize(buff.Size, fieldPath.Child("size"))...)
	}
	return allErrs
}

func validateUpstreamLBMethod(lBMethod string, fieldPath *field.Path, isPlus bool) field.ErrorList {
	if lBMethod == "" {
		return nil
	}

	if isPlus {
		_, err := configs.ParseLBMethodForPlus(lBMethod)
		if err != nil {
			return field.ErrorList{field.Invalid(fieldPath, lBMethod, err.Error())}
		}
	} else {
		_, err := configs.ParseLBMethod(lBMethod)
		if err != nil {
			return field.ErrorList{field.Invalid(fieldPath, lBMethod, err.Error())}
		}
	}
	return nil
}

func validateUpstreamHealthCheck(hc *v1.HealthCheck, typeName string, fieldPath *field.Path) field.ErrorList {
	if hc == nil {
		return nil
	}

	allErrs := validateGrpcHealthCheck(hc, typeName, fieldPath)
	if hc.Path != "" {
		allErrs = append(allErrs, validatePath(hc.Path, fieldPath.Child("path"))...)
	}

	allErrs = append(allErrs, validateTime(hc.Interval, fieldPath.Child("interval"))...)
	allErrs = append(allErrs, validateTime(hc.Jitter, fieldPath.Child("jitter"))...)
	allErrs = append(allErrs, validatePositiveIntOrZero(hc.Fails, fieldPath.Child("fails"))...)
	allErrs = append(allErrs, validatePositiveIntOrZero(hc.Passes, fieldPath.Child("passes"))...)
	allErrs = append(allErrs, validateTime(hc.ConnectTimeout, fieldPath.Child("connect-timeout"))...)
	allErrs = append(allErrs, validateTime(hc.ReadTimeout, fieldPath.Child("read-timeout"))...)
	allErrs = append(allErrs, validateTime(hc.SendTimeout, fieldPath.Child("send-timeout"))...)
	allErrs = append(allErrs, validateStatusMatch(hc.StatusMatch, fieldPath.Child("statusMatch"))...)
	allErrs = append(allErrs, validateTime(hc.KeepaliveTime, fieldPath.Child("keepalive-time"))...)

	for i, header := range hc.Headers {
		idxPath := fieldPath.Child("headers").Index(i)
		allErrs = append(allErrs, validateHeader(header, idxPath)...)
	}

	if hc.Port > 0 {
		for _, msg := range validation.IsValidPortNum(hc.Port) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("port"), hc.Port, msg))
		}
	}

	if hc.Persistent && !hc.Mandatory {
		allErrs = append(allErrs, field.Required(fieldPath.Child("mandatory"), "must be true when `persistent` is true"))
	}

	return allErrs
}

func validateGrpcHealthCheck(hc *v1.HealthCheck, typeName string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if typeName != "grpc" {
		if hc.GRPCStatus != nil {
			allErrs = append(allErrs, field.Forbidden(fieldPath.Child("grpcStatus"), "cannot specify `grpcStatus` on http type health checks"))
		}
		if hc.GRPCService != "" {
			allErrs = append(allErrs, field.Forbidden(fieldPath.Child("grpcService"), "cannot specify `grpcService` on http type health checks"))
		}
		return allErrs
	}

	if hc.Path != "" {
		allErrs = append(allErrs, field.Forbidden(fieldPath.Child("path"), "cannot specify `path` on gRPC type health checks"))
	}
	if hc.StatusMatch != "" {
		allErrs = append(allErrs, field.Forbidden(fieldPath.Child("statusMatch"), "cannot specify `statusMatch` on gRPC type health checks"))
	}

	allErrs = append(allErrs, validateGrpcStatus(hc.GRPCStatus, fieldPath.Child("grpcStatus"))...)

	allErrs = append(allErrs, validateGrpcService(hc.GRPCService, fieldPath.Child("grpcService"))...)

	return allErrs
}

func validateGrpcStatus(i *int, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if i != nil {
		if msg := validateGrpcStatusCode(i); msg != "" {
			allErrs = append(allErrs, field.Invalid(fieldPath, i, msg))
		}
	}

	return allErrs
}

// validateSessionCookie implements validation rules for session cookies.
//
// [Ref.]: https://nginx.org/en/docs/http/ngx_http_upstream_module.html#sticky
func validateSessionCookie(sc *v1.SessionCookie, fieldPath *field.Path) field.ErrorList {
	if sc == nil {
		return nil
	}

	allErrs := field.ErrorList{}
	if sc.Name == "" {
		allErrs = append(allErrs, field.Required(fieldPath.Child("name"), ""))
	} else {
		for _, msg := range isCookieName(sc.Name) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("name"), sc.Name, msg))
		}
	}

	if sc.Path != "" {
		allErrs = append(allErrs, validatePath(sc.Path, fieldPath.Child("path"))...)
	}

	if sc.Expires != "max" {
		allErrs = append(allErrs, validateTime(sc.Expires, fieldPath.Child("expires"))...)
	}

	if sc.Domain != "" {
		// A Domain prefix of "." is allowed.
		domain := strings.TrimPrefix(sc.Domain, ".")
		for _, msg := range validation.IsDNS1123Subdomain(domain) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("domain"), sc.Domain, msg))
		}
	}

	if sc.SameSite != "" {
		switch strings.ToLower(sc.SameSite) {
		case "strict", "lax", "none":
		default:
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("samesite"), sc.SameSite, "must be one of: `strict`, `lax`, `none`"))
		}
	}
	return allErrs
}

// validateUpstreamType validates that the protocol type of the upstream is of a supported protocol.
// Current supported protocols are "http" and "grpc". If unset, it will default to "http".
func validateUpstreamType(typeName string, fieldPath *field.Path) field.ErrorList {
	if typeName == "" {
		return nil
	}

	switch typeName {
	case "grpc", "http":
		return nil
	default:
		return field.ErrorList{field.Invalid(fieldPath, typeName, "must be one of `grpc` or `http`")}
	}
}

func validateStatusMatch(s string, fieldPath *field.Path) field.ErrorList {
	if s == "" {
		return nil
	}

	allErrs := field.ErrorList{}
	if strings.HasPrefix(s, "!") {
		if !strings.HasPrefix(s, "! ") {
			allErrs = append(allErrs, field.Invalid(fieldPath, s, "must have an space character after the `!`"))
		}
	}

	statuses := strings.Split(s, " ")
	for i, value := range statuses {
		if value == "!" {
			if i != 0 {
				allErrs = append(allErrs, field.Invalid(fieldPath, s, "`!` can only appear once at the beginning"))
			}
		} else if strings.Contains(value, "-") {
			if msg := validateStatusCodeRange(value); msg != "" {
				allErrs = append(allErrs, field.Invalid(fieldPath, s, msg))
			}
		} else if msg := validateStatusCode(value); msg != "" {
			allErrs = append(allErrs, field.Invalid(fieldPath, s, msg))
		}
	}
	return allErrs
}

func validateStatusCodeRange(statusRangeStr string) string {
	statusRange := strings.Split(statusRangeStr, "-")
	if len(statusRange) != 2 {
		return "ranges must only have 2 numbers"
	}

	min, msg := validateIntFromString(statusRange[0])
	if msg != "" {
		return msg
	}

	max, msg := validateIntFromString(statusRange[1])
	if msg != "" {
		return msg
	}

	for _, code := range statusRange {
		if msg := validateStatusCode(code); msg != "" {
			return msg
		}
	}

	if max <= min {
		return fmt.Sprintf("range limits must be %v < %v", min, max)
	}

	return ""
}

func validateIntFromString(number string) (int, string) {
	numberInt, err := strconv.ParseInt(number, 10, 64)
	if err != nil {
		return 0, fmt.Sprintf("%v must be a valid integer", number)
	}

	return int(numberInt), ""
}

func validateStatusCode(status string) string {
	code, errMsg := validateIntFromString(status)
	if errMsg != "" {
		return errMsg
	}

	if code < 100 || code > 999 {
		return validation.InclusiveRangeError(100, 999)
	}

	return ""
}

func validateGrpcStatusCode(code *int) string {
	if *code < 0 || *code > 16 {
		return validation.InclusiveRangeError(0, 16)
	}

	return ""
}

func validateHeader(h v1.Header, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if h.Name == "" {
		allErrs = append(allErrs, field.Required(fieldPath.Child("name"), ""))
	}

	for _, msg := range validation.IsHTTPHeaderName(h.Name) {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("name"), h.Name, msg))
	}

	for _, msg := range isValidHeaderValue(h.Value) {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("value"), h.Value, msg))
	}

	return allErrs
}

const (
	headerValueFmt              = `([^"$\\]|\\[^$])*`
	headerValueFmtErrMsg string = `a valid header must have all '"' escaped and must not contain any '$' or end with an unescaped '\'`
)

var headerValueFmtRegexp = regexp.MustCompile("^" + headerValueFmt + "$")

func isValidHeaderValue(s string) []string {
	if !headerValueFmtRegexp.MatchString(s) {
		return []string{validation.RegexError(headerValueFmtErrMsg, headerValueFmt, "my.service", "foo")}
	}
	return nil
}

func (vsv *VirtualServerValidator) validateUpstreams(upstreams []v1.Upstream, fieldPath *field.Path) (allErrs field.ErrorList, upstreamNames sets.Set[string]) {
	allErrs = field.ErrorList{}
	upstreamNames = sets.Set[string]{}

	for i, u := range upstreams {
		u := u // address gosec G601
		idxPath := fieldPath.Index(i)

		upstreamErrors := validateUpstreamName(u.Name, idxPath.Child("name"))
		if len(upstreamErrors) > 0 {
			allErrs = append(allErrs, upstreamErrors...)
		} else if upstreamNames.Has(u.Name) {
			allErrs = append(allErrs, field.Duplicate(idxPath.Child("name"), u.Name))
		} else {
			upstreamNames.Insert(u.Name)
		}
		if u.UseClusterIP && u.Subselector != nil {
			allErrs = append(allErrs, field.Forbidden(idxPath.Child("subselector"), "subselector can't be used with use-cluster-ip"))
		} else {
			allErrs = append(allErrs, validateLabels(u.Subselector, idxPath.Child("subselector"))...)
		}

		allErrs = append(allErrs, validateServiceName(u.Service, idxPath.Child("service"))...)
		allErrs = append(allErrs, validateTime(u.ProxyConnectTimeout, idxPath.Child("connect-timeout"))...)
		allErrs = append(allErrs, validateTime(u.ProxyReadTimeout, idxPath.Child("read-timeout"))...)
		allErrs = append(allErrs, validateTime(u.ProxySendTimeout, idxPath.Child("send-timeout"))...)
		allErrs = append(allErrs, validateNextUpstream(u.ProxyNextUpstream, idxPath.Child("next-upstream"))...)
		allErrs = append(allErrs, validateTime(u.ProxyNextUpstreamTimeout, idxPath.Child("next-upstream-timeout"))...)
		allErrs = append(allErrs, validatePositiveIntOrZeroFromPointer(&u.ProxyNextUpstreamTries, idxPath.Child("next-upstream-tries"))...)
		allErrs = append(allErrs, validateUpstreamLBMethod(u.LBMethod, idxPath.Child("lb-method"), vsv.isPlus)...)
		allErrs = append(allErrs, validateTime(u.FailTimeout, idxPath.Child("fail-timeout"))...)
		allErrs = append(allErrs, validatePositiveIntOrZeroFromPointer(u.MaxFails, idxPath.Child("max-fails"))...)
		allErrs = append(allErrs, validatePositiveIntOrZeroFromPointer(u.Keepalive, idxPath.Child("keepalive"))...)
		allErrs = append(allErrs, validatePositiveIntOrZeroFromPointer(u.MaxConns, idxPath.Child("max-conns"))...)
		allErrs = append(allErrs, validateOffset(u.ClientMaxBodySize, idxPath.Child("client-max-body-size"))...)
		allErrs = append(allErrs, validateUpstreamHealthCheck(u.HealthCheck, u.Type, idxPath.Child("healthCheck"))...)
		allErrs = append(allErrs, validateTime(u.SlowStart, idxPath.Child("slow-start"))...)
		allErrs = append(allErrs, validateBuffer(u.ProxyBuffers, idxPath.Child("buffers"))...)
		allErrs = append(allErrs, validateSize(u.ProxyBufferSize, idxPath.Child("buffer-size"))...)
		allErrs = append(allErrs, validateSize(u.ProxyBusyBuffersSize, idxPath.Child("busy-buffers-size"))...)
		allErrs = append(allErrs, validateQueue(u.Queue, idxPath.Child("queue"))...)
		allErrs = append(allErrs, validateSessionCookie(u.SessionCookie, idxPath.Child("sessionCookie"))...)
		allErrs = append(allErrs, validateUpstreamType(u.Type, idxPath.Child("type"))...)

		for _, msg := range validation.IsValidPortNum(int(u.Port)) {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("port"), u.Port, msg))
		}

		allErrs = append(allErrs, validateBackup(u.Backup, u.BackupPort, u.LBMethod, idxPath)...)

		allErrs = append(allErrs, rejectPlusResourcesInOSS(u, idxPath, vsv.isPlus)...)

	}
	return allErrs, upstreamNames
}

// validateBackup validates backup service name and port semantics and business logic.
//
// Backup can't be used with load balancing methods: 'hash', 'hash_ip' and 'random'.
// Ref.: https://nginx.org/en/docs/http/ngx_http_upstream_module.html
func validateBackup(backup string, backupPort *uint16, lbMethod string, idxPath *field.Path) field.ErrorList {
	if backup == "" && backupPort == nil {
		return nil
	}
	allErrs := field.ErrorList{}
	if backup != "" && backupPort == nil {
		allErrs = append(allErrs, field.Invalid(idxPath.Child("backupPort"), backupPort, "both backup and backup port must be specified"))
	}
	if backup == "" && backupPort != nil {
		allErrs = append(allErrs, field.Invalid(idxPath.Child("backup"), backup, "both backup and backup port must be specified"))
	}

	if strings.Contains(lbMethod, "hash") || strings.Contains(lbMethod, "hash_ip") || strings.Contains(lbMethod, "random") {
		allErrs = append(allErrs, field.Forbidden(idxPath.Child("backup"),
			"backup cannot be used along with the 'hash', 'hash_ip' and 'random' load balancing methods",
		))
	}

	allErrs = append(allErrs, validateBackupName(backup, idxPath.Child("backup"))...)
	allErrs = append(allErrs, validateBackupPortFromPointer(backupPort, idxPath.Child("backupPort"))...)
	return allErrs
}

var validNextUpstreamParams = map[string]bool{
	"error":          true,
	"timeout":        true,
	"invalid_header": true,
	"http_500":       true,
	"http_502":       true,
	"http_503":       true,
	"http_504":       true,
	"http_403":       true,
	"http_404":       true,
	"http_429":       true,
	"non_idempotent": true,
	"off":            true,
	"":               true,
}

// validateNextUpstream checks the values given for passing queries to a upstream
func validateNextUpstream(nextUpstream string, fieldPath *field.Path) field.ErrorList {
	if nextUpstream == "" {
		return nil
	}

	allErrs := field.ErrorList{}
	allParams := sets.Set[string]{}

	params := strings.Fields(nextUpstream)
	for _, para := range params {
		if !validNextUpstreamParams[para] {
			allErrs = append(allErrs, field.Invalid(fieldPath, para, "not a valid parameter"))
		}
		if allParams.Has(para) {
			allErrs = append(allErrs, field.Invalid(fieldPath, para, "can not have duplicate parameters"))
		} else {
			allParams.Insert(para)
		}
	}
	return allErrs
}

// validateUpstreamName checks is an upstream name is valid.
// The rules for NGINX upstream names are less strict than IsDNS1035Label.
// However, it is convenient to enforce IsDNS1035Label in the yaml for
// the names of upstreams.
func validateUpstreamName(name string, fieldPath *field.Path) field.ErrorList {
	return validateDNS1035Label(name, fieldPath)
}

// validateServiceName checks if a service name is valid.
// It performs the same validation as ValidateServiceName from k8s.io/kubernetes/pkg/apis/core/validation/validation.go.
func validateServiceName(name string, fieldPath *field.Path) field.ErrorList {
	return validateDNS1035Label(name, fieldPath)
}

func validateDNS1035Label(name string, fieldPath *field.Path) field.ErrorList {
	if name == "" {
		return field.ErrorList{field.Required(fieldPath, "")}
	}

	allErrs := field.ErrorList{}
	for _, msg := range validation.IsDNS1035Label(name) {
		allErrs = append(allErrs, field.Invalid(fieldPath, name, msg))
	}
	return allErrs
}

func (vsv *VirtualServerValidator) validateVirtualServerRoutes(routes []v1.Route, fieldPath *field.Path, upstreamNames sets.Set[string], namespace string) field.ErrorList {
	allErrs := field.ErrorList{}

	allPaths := sets.Set[string]{}

	for i, r := range routes {
		idxPath := fieldPath.Index(i)

		isRouteFieldForbidden := false
		routeErrs := vsv.validateRoute(r, idxPath, upstreamNames, isRouteFieldForbidden, namespace)
		if len(routeErrs) > 0 {
			allErrs = append(allErrs, routeErrs...)
		} else if allPaths.Has(r.Path) {
			allErrs = append(allErrs, field.Duplicate(idxPath.Child("path"), r.Path))
		} else {
			allPaths.Insert(r.Path)
		}
	}

	return allErrs
}

func (vsv *VirtualServerValidator) validateRoute(route v1.Route, fieldPath *field.Path, upstreamNames sets.Set[string], isRouteFieldForbidden bool, namespace string) field.ErrorList {
	allErrs := validateRoutePath(route.Path, fieldPath.Child("path"))
	allErrs = append(allErrs, validatePolicies(route.Policies, fieldPath.Child("policies"), namespace)...)

	fieldCount := 0

	if route.Action != nil {
		allErrs = append(allErrs, vsv.validateAction(route.Action, fieldPath.Child("action"), upstreamNames, route.Path, false)...)
		fieldCount++
	}

	if len(route.Splits) > 0 {
		allErrs = append(allErrs, vsv.validateSplits(route.Splits, fieldPath.Child("splits"), upstreamNames, route.Path)...)
		fieldCount++
	}

	// Matches are optional. that's why we don't do fieldCount++
	if len(route.Matches) > 0 {
		for i, m := range route.Matches {
			allErrs = append(allErrs, vsv.validateMatch(m, fieldPath.Child("matches").Index(i), upstreamNames, route.Path)...)
		}
	}

	for i, e := range route.ErrorPages {
		allErrs = append(allErrs, vsv.validateErrorPage(e, fieldPath.Child("errorPages").Index(i))...)
	}

	if route.Route != "" {
		if isRouteFieldForbidden {
			allErrs = append(allErrs, field.Forbidden(fieldPath.Child("route"), "is not allowed"))
		} else {
			allErrs = append(allErrs, validateRouteField(route.Route, fieldPath.Child("route"))...)
			fieldCount++
		}
	}

	if fieldCount != 1 {
		msg := "must specify exactly one of `action`, `splits` or `route`"
		if isRouteFieldForbidden || len(route.Matches) > 0 {
			msg = "must specify exactly one of `action` or `splits`"
		}

		allErrs = append(allErrs, field.Invalid(fieldPath, "", msg))
	}

	allErrs = append(allErrs, validateDos(vsv.isDosEnabled, route.Dos, fieldPath.Child("dos"))...)

	return allErrs
}

func errorPageHasRequiredFields(errorPage v1.ErrorPage) bool {
	var count int

	if errorPage.Return != nil {
		count++
	}

	if errorPage.Redirect != nil {
		count++
	}

	return count == 1
}

func (vsv *VirtualServerValidator) validateErrorPage(errorPage v1.ErrorPage, fieldPath *field.Path) field.ErrorList {
	if !errorPageHasRequiredFields(errorPage) {
		return field.ErrorList{field.Required(fieldPath, "must specify exactly one of `redirect` or `return`")}
	}
	if len(errorPage.Codes) == 0 {
		return field.ErrorList{field.Required(fieldPath.Child("codes"), "must include at least 1 status code in `codes`")}
	}

	allErrs := field.ErrorList{}
	for i, c := range errorPage.Codes {
		for _, msg := range validation.IsInRange(c, 300, 599) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("codes").Index(i), c, msg))
		}
	}

	if errorPage.Return != nil {
		allErrs = append(allErrs, vsv.validateErrorPageReturn(errorPage.Return, fieldPath.Child("return"))...)
	}

	if errorPage.Redirect != nil {
		allErrs = append(allErrs, vsv.validateErrorPageRedirect(errorPage.Redirect, fieldPath.Child("redirect"))...)
	}
	return allErrs
}

var errorPageReturnBodyVariable = map[string]bool{"upstream_status": true}

func (vsv *VirtualServerValidator) validateErrorPageReturn(r *v1.ErrorPageReturn, fieldPath *field.Path) field.ErrorList {
	allErrs := vsv.validateActionReturn(&r.ActionReturn, fieldPath, nil, errorPageReturnBodyVariable)

	for i, header := range r.Headers {
		allErrs = append(allErrs, vsv.validateErrorPageHeader(header, fieldPath.Child("headers").Index(i))...)
	}
	return allErrs
}

var errorPageHeaderValueVariables = map[string]bool{"upstream_status": true}

func (vsv *VirtualServerValidator) validateErrorPageHeader(h v1.Header, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if h.Name == "" {
		allErrs = append(allErrs, field.Required(fieldPath.Child("name"), ""))
	}

	for _, msg := range validation.IsHTTPHeaderName(h.Name) {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("name"), h.Name, msg))
	}

	if err := ValidateEscapedString(h.Value, "value", `\"${status}\"`); err != nil {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("value"), h.Value, err.Error()))
	}

	allErrs = append(allErrs, validateStringWithVariables(h.Value, fieldPath.Child("value"), nil, errorPageHeaderValueVariables, vsv.isPlus)...)

	return allErrs
}

var validErrorPageRedirectVariables = map[string]bool{"scheme": true, "http_x_forwarded_proto": true}

func (vsv *VirtualServerValidator) validateErrorPageRedirect(r *v1.ErrorPageRedirect, fieldPath *field.Path) field.ErrorList {
	return vsv.validateActionRedirect(&r.ActionRedirect, fieldPath, validErrorPageRedirectVariables)
}

func countActions(action *v1.Action) int {
	var count int
	if action.Pass != "" {
		count++
	}

	if action.Redirect != nil {
		count++
	}

	if action.Return != nil {
		count++
	}

	if action.Proxy != nil {
		count++
	}

	return count
}

// returnBodyVariables includes NGINX variables allowed to be used in a return body.
var returnBodyVariables = map[string]bool{
	"request_uri":         true,
	"request_method":      true,
	"request_body":        true,
	"scheme":              true,
	"args":                true,
	"host":                true,
	"request_time":        true,
	"request_length":      true,
	"nginx_version":       true,
	"pid":                 true,
	"connection":          true,
	"remote_addr":         true,
	"remote_port":         true,
	"time_iso8601":        true,
	"time_local":          true,
	"server_addr":         true,
	"server_port":         true,
	"server_name":         true,
	"server_protocol":     true,
	"connections_active":  true,
	"connections_reading": true,
	"connections_writing": true,
	"connections_waiting": true,
}

var returnBodySpecialVariables = []string{"arg_", "http_", "cookie_"}

// validRedirectVariableNames includes NGINX variables allowed to be used in redirects.
var validRedirectVariableNames = map[string]bool{
	"scheme":                 true,
	"http_x_forwarded_proto": true,
	"request_uri":            true,
	"host":                   true,
}

func (vsv *VirtualServerValidator) validateAction(action *v1.Action, fieldPath *field.Path, upstreamNames sets.Set[string], path string, internal bool) field.ErrorList {
	if countActions(action) != 1 {
		return field.ErrorList{field.Required(fieldPath, "action must specify exactly one of `pass`, `redirect`, `return` or `proxy`")}
	}

	allErrs := field.ErrorList{}
	if action.Pass != "" {
		allErrs = append(allErrs, validateReferencedUpstream(action.Pass, fieldPath.Child("pass"), upstreamNames)...)
	}

	if action.Redirect != nil {
		allErrs = append(allErrs, vsv.validateActionRedirect(action.Redirect, fieldPath.Child("redirect"), validRedirectVariableNames)...)
	}

	if action.Return != nil {
		allErrs = append(allErrs, vsv.validateActionReturn(action.Return, fieldPath.Child("return"), returnBodySpecialVariables, returnBodyVariables)...)
	}

	if action.Proxy != nil {
		allErrs = append(allErrs, vsv.validateActionProxy(action.Proxy, fieldPath.Child("proxy"), upstreamNames, path, internal)...)
	}

	return allErrs
}

func (vsv *VirtualServerValidator) validateActionRedirect(redirect *v1.ActionRedirect, fieldPath *field.Path, validVars map[string]bool) field.ErrorList {
	allErrs := vsv.validateRedirectURL(redirect.URL, fieldPath.Child("url"), validVars)

	if redirect.Code != 0 {
		allErrs = append(allErrs, validateRedirectStatusCode(redirect.Code, fieldPath.Child("code"))...)
	}
	return allErrs
}

var nginxVariableRegexp = regexp.MustCompile(`\$\{([^}]*)\}`)

// captureVariables returns a slice of vars enclosed in ${}. For example "${a} ${b}" would return ["a", "b"].
func captureVariables(s string) []string {
	var nVars []string

	res := nginxVariableRegexp.FindAllStringSubmatch(s, -1)
	for _, n := range res {
		nVars = append(nVars, n[1])
	}

	return nVars
}

func (vsv *VirtualServerValidator) validateRedirectURL(redirectURL string, fieldPath *field.Path, validVars map[string]bool) field.ErrorList {
	if redirectURL == "" {
		return field.ErrorList{field.Required(fieldPath, "must specify a url")}
	}
	if !strings.Contains(redirectURL, "://") {
		return field.ErrorList{field.Invalid(fieldPath, redirectURL, "must contain the protocol with '://', for example http://, https:// or ${scheme}://")}
	}
	if err := ValidateEscapedString(redirectURL, "http://www.nginx.com", "${scheme}://${host}/green/", `\"http://www.nginx.com\"`); err != nil {
		return field.ErrorList{field.Invalid(fieldPath, redirectURL, err.Error())}
	}
	return validateStringWithVariables(redirectURL, fieldPath, nil, validVars, vsv.isPlus)
}

func validateActionReturnCode(code int, fieldPath *field.Path) field.ErrorList {
	if (code >= 200 && code <= 299) || (code >= 400 && code <= 599) {
		return nil
	}
	msg := "must be a valid status code either 2XX, 4XX or 5XX, for example, 200 or 402."
	return field.ErrorList{field.Invalid(fieldPath, code, msg)}
}

func (vsv *VirtualServerValidator) validateActionReturn(r *v1.ActionReturn, fieldPath *field.Path, specialValidVars []string, validVars map[string]bool) field.ErrorList {
	if r.Body == "" {
		return field.ErrorList{field.Required(fieldPath.Child("body"), "")}
	}

	allErrs := validateEscapedStringWithVariables(r.Body, fieldPath.Child("body"), specialValidVars, validVars, vsv.isPlus)
	if r.Type != "" {
		allErrs = append(allErrs, validateActionReturnType(r.Type, fieldPath.Child("type"))...)
	}
	if r.Code != 0 {
		allErrs = append(allErrs, validateActionReturnCode(r.Code, fieldPath.Child("code"))...)
	}
	return allErrs
}

func validateEscapedStringWithVariables(body string, fieldPath *field.Path, specialValidVars []string, validVars map[string]bool, isPlus bool) field.ErrorList {
	allErrs := field.ErrorList{}

	if err := ValidateEscapedString(body, `Hello World! \n`, `\"${request_uri}\" is unavailable. \n`); err != nil {
		allErrs = append(allErrs, field.Invalid(fieldPath, body, err.Error()))
	}

	allErrs = append(allErrs, validateStringWithVariables(body, fieldPath, specialValidVars, validVars, isPlus)...)

	return allErrs
}

var (
	actionReturnTypeFmt = `([^;\{\}"\\]|\\.)*`
	actionReturnTypeErr = `must have all '"' (double quotes), '{', '}' or ';' escaped and must not end with an unescaped '\' (backslash)`
)

var actionReturnTypeRegexp = regexp.MustCompile("^" + actionReturnTypeFmt + "$")

func validateActionReturnType(returnType string, fieldPath *field.Path) field.ErrorList {
	if !actionReturnTypeRegexp.MatchString(returnType) {
		msg := validation.RegexError(actionReturnTypeErr, actionReturnTypeFmt, "type/subtype", "application/json")
		return field.ErrorList{field.Invalid(fieldPath, returnType, msg)}
	}
	return nil
}

func validateRouteField(value string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for _, msg := range validation.IsQualifiedName(value) {
		allErrs = append(allErrs, field.Invalid(fieldPath, value, msg))
	}

	return allErrs
}

func validateReferencedUpstream(name string, fieldPath *field.Path, upstreamNames sets.Set[string]) field.ErrorList {
	allErrs := field.ErrorList{}

	upstreamErrs := validateUpstreamName(name, fieldPath)
	if len(upstreamErrs) > 0 {
		allErrs = append(allErrs, upstreamErrs...)
	} else if !upstreamNames.Has(name) {
		allErrs = append(allErrs, field.NotFound(fieldPath, name))
	}

	return allErrs
}

func (vsv *VirtualServerValidator) validateActionProxy(p *v1.ActionProxy, fieldPath *field.Path, upstreamNames sets.Set[string], path string, internal bool) field.ErrorList {
	allErrs := validateReferencedUpstream(p.Upstream, fieldPath.Child("upstream"), upstreamNames)
	allErrs = append(allErrs, vsv.validateActionProxyRequestHeaders(p.RequestHeaders, fieldPath.Child("requestHeaders"))...)
	allErrs = append(allErrs, vsv.validateActionProxyResponseHeaders(p.ResponseHeaders, fieldPath.Child("responseHeaders"))...)

	if strings.HasPrefix(path, "~") || internal {
		allErrs = append(allErrs, validateActionProxyRewritePathForRegexp(p.RewritePath, fieldPath.Child("rewritePath"))...)
	} else {
		allErrs = append(allErrs, validateActionProxyRewritePath(p.RewritePath, fieldPath.Child("rewritePath"))...)
	}

	return allErrs
}

func validateStringNoVariables(s string, fieldPath *field.Path) field.ErrorList {
	for i, char := range s {
		charLen := len(string(char))
		if string(char) == "$" && i+charLen < len(s) {
			if _, err := strconv.Atoi(string(s[i+charLen])); err != nil {
				return field.ErrorList{field.Invalid(fieldPath, s, "`$` character can be only followed by a number")}
			}
		}
	}
	return nil
}

func validateActionProxyRewritePath(rewritePath string, fieldPath *field.Path) field.ErrorList {
	if rewritePath == "" {
		return nil
	}
	allErrs := validateStringNoVariables(rewritePath, fieldPath)
	return append(allErrs, validatePath(rewritePath, fieldPath)...)
}

func validateActionProxyRewritePathForRegexp(rewritePath string, fieldPath *field.Path) field.ErrorList {
	if rewritePath == "" {
		return nil
	}

	allErrs := validateStringNoVariables(rewritePath, fieldPath)
	if err := ValidateEscapedString(rewritePath, "/rewrite$1", "/images"); err != nil {
		allErrs = append(allErrs, field.Invalid(fieldPath, rewritePath, err.Error()))
	}
	return allErrs
}

var actionProxyHeaderVariables = map[string]bool{
	"request_uri":             true,
	"request_method":          true,
	"request_body":            true,
	"scheme":                  true,
	"args":                    true,
	"host":                    true,
	"request_time":            true,
	"request_length":          true,
	"nginx_version":           true,
	"pid":                     true,
	"connection":              true,
	"remote_addr":             true,
	"remote_port":             true,
	"time_iso8601":            true,
	"time_local":              true,
	"server_addr":             true,
	"server_port":             true,
	"server_name":             true,
	"server_protocol":         true,
	"connections_active":      true,
	"connections_reading":     true,
	"connections_writing":     true,
	"connections_waiting":     true,
	"ssl_cipher":              true,
	"ssl_ciphers":             true,
	"ssl_client_cert":         true,
	"ssl_client_escaped_cert": true,
	"ssl_client_fingerprint":  true,
	"ssl_client_i_dn":         true,
	"ssl_client_i_dn_legacy":  true,
	"ssl_client_raw_cert":     true,
	"ssl_client_s_dn":         true,
	"ssl_client_s_dn_legacy":  true,
	"ssl_client_serial":       true,
	"ssl_client_v_end":        true,
	"ssl_client_v_remain":     true,
	"ssl_client_v_start":      true,
	"ssl_client_verify":       true,
	"ssl_curves":              true,
	"ssl_early_data":          true,
	"ssl_protocol":            true,
	"ssl_server_name":         true,
	"ssl_session_id":          true,
	"ssl_session_reused":      true,
}

var actionProxyHeaderSpecialVariables = []string{"arg_", "http_", "cookie_", "jwt_claim_", "jwt_header_"}

func (vsv *VirtualServerValidator) validateActionProxyHeader(h v1.Header, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if h.Name == "" {
		allErrs = append(allErrs, field.Required(fieldPath.Child("name"), ""))
	}

	for _, msg := range validation.IsHTTPHeaderName(h.Name) {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("name"), h.Name, msg))
	}

	allErrs = append(allErrs, validateEscapedStringWithVariables(h.Value, fieldPath.Child("value"),
		actionProxyHeaderSpecialVariables, actionProxyHeaderVariables, vsv.isPlus)...)

	return allErrs
}

func (vsv *VirtualServerValidator) validateActionProxyRequestHeaders(requestHeaders *v1.ProxyRequestHeaders, fieldPath *field.Path) field.ErrorList {
	if requestHeaders == nil {
		return nil
	}

	allErrs := field.ErrorList{}
	for i, header := range requestHeaders.Set {
		allErrs = append(allErrs, vsv.validateActionProxyHeader(header, fieldPath.Index(i))...)
	}
	return allErrs
}

func (vsv *VirtualServerValidator) validateActionProxyResponseHeaders(responseHeaders *v1.ProxyResponseHeaders, fieldPath *field.Path) field.ErrorList {
	if responseHeaders == nil {
		return nil
	}

	allErrs := field.ErrorList{}
	for i, header := range responseHeaders.Hide {
		for _, msg := range validation.IsHTTPHeaderName(header) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("hide").Index(i), header, msg))
		}
	}

	for i, header := range responseHeaders.Pass {
		for _, msg := range validation.IsHTTPHeaderName(header) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("pass").Index(i), header, msg))
		}
	}

	for i, header := range responseHeaders.Add {
		allErrs = append(allErrs, vsv.validateActionProxyHeader(header.Header, fieldPath.Child("add").Index(i))...)
	}

	allErrs = append(allErrs, validateIgnoreHeaders(responseHeaders.Ignore, fieldPath.Child("ignore"))...)

	return allErrs
}

var validIgnoreHeaders = map[string]bool{
	"X-Accel-Redirect":   true,
	"X-Accel-Expires":    true,
	"X-Accel-Limit-Rate": true,
	"X-Accel-Buffering":  true,
	"X-Accel-Charset":    true,
	"Expires":            true,
	"Cache-Control":      true,
	"Set-Cookie":         true,
	"Vary":               true,
}

func validateIgnoreHeaders(ignoreHeaders []string, fieldPath *field.Path) field.ErrorList {
	if len(ignoreHeaders) == 0 {
		return nil
	}

	allErrs := field.ErrorList{}
	for i, h := range ignoreHeaders {
		if !validIgnoreHeaders[h] {
			msg := fmt.Sprintf("not a valid ignore header name. Accepted headers are : %v", mapToPrettyString(validIgnoreHeaders))
			allErrs = append(allErrs, field.Invalid(fieldPath.Index(i), h, msg))
		}
	}
	return allErrs
}

func (vsv *VirtualServerValidator) validateSplits(splits []v1.Split, fieldPath *field.Path, upstreamNames sets.Set[string], path string) field.ErrorList {
	if len(splits) < 2 {
		return field.ErrorList{field.Invalid(fieldPath, "", "must include at least 2 splits")}
	}

	allErrs := field.ErrorList{}
	totalWeight := 0
	for i, s := range splits {
		idxPath := fieldPath.Index(i)

		for _, msg := range validation.IsInRange(s.Weight, 0, 100) {
			allErrs = append(allErrs, field.Invalid(idxPath.Child("weight"), s.Weight, msg))
		}

		if s.Action == nil {
			allErrs = append(allErrs, field.Required(idxPath.Child("action"), ""))
		} else {
			allErrs = append(allErrs, vsv.validateAction(s.Action, idxPath.Child("action"), upstreamNames, path, true)...)
		}

		totalWeight += s.Weight
	}

	if totalWeight != 100 {
		allErrs = append(allErrs, field.Invalid(fieldPath, "", "the sum of the weights of all splits must be equal to 100"))
	}

	return allErrs
}

// We support prefix-based NGINX locations, positive case-sensitive/insensitive regular expressions matches and exact matches.
// More info http://nginx.org/en/docs/http/ngx_http_core_module.html#location
func validateRoutePath(path string, fieldPath *field.Path) field.ErrorList {
	if path == "" {
		return field.ErrorList{field.Required(fieldPath, "")}
	}

	allErrs := field.ErrorList{}
	if strings.HasPrefix(path, "~") {
		allErrs = append(allErrs, validateRegexPath(path, fieldPath)...)
	} else if strings.HasPrefix(path, "/") {
		allErrs = append(allErrs, validatePath(path, fieldPath)...)
	} else if strings.HasPrefix(path, "=") {
		allErrs = append(allErrs, validatePath(strings.TrimPrefix(path, "="), fieldPath)...)
	} else {
		allErrs = append(allErrs, field.Invalid(fieldPath, path, "must start with /, ~ or ="))
	}
	return allErrs
}

// validateRegexPath validates correctness of the string representing the path.
//
// Internally it uses Perl5 compatible regexp2 package.
func validateRegexPath(path string, fieldPath *field.Path) field.ErrorList {
	if _, err := regexp2.Compile(path, 0); err != nil {
		return field.ErrorList{field.Invalid(fieldPath, path, fmt.Sprintf("must be a valid regular expression: %v", err))}
	}
	if err := ValidateEscapedString(path, "*.jpg", "^/images/image_*.png$"); err != nil {
		return field.ErrorList{field.Invalid(fieldPath, path, err.Error())}
	}
	return nil
}

const (
	pathFmt    = `/[^\s{};\\]*`
	pathErrMsg = "must start with / and must not include any whitespace character, `{`, `}` or `;`"
)

var pathRegexp = regexp.MustCompile("^" + pathFmt + "$")

func validatePath(path string, fieldPath *field.Path) field.ErrorList {
	if path == "" {
		return field.ErrorList{field.Required(fieldPath, "")}
	}
	if !pathRegexp.MatchString(path) {
		msg := validation.RegexError(pathErrMsg, pathFmt, "/", "/path", "/path/subpath-123")
		return field.ErrorList{field.Invalid(fieldPath, path, msg)}
	}
	return nil
}

const (
	grpcFmt    = `[^\s{};]*`
	grpcErrMsg = "must not include any whitespace character, `{`, `}`, or `;`"
)

var grpcRegexp = regexp.MustCompile("^" + grpcFmt + "$")

func validateGrpcService(service string, fieldPath *field.Path) field.ErrorList {
	if service == "" {
		return nil
	}
	if !grpcRegexp.MatchString(service) {
		msg := validation.RegexError(grpcErrMsg, grpcFmt, "GrpcService", "GrpcService.MyService")
		return field.ErrorList{field.Invalid(fieldPath, service, msg)}
	}
	return nil
}

func (vsv *VirtualServerValidator) validateMatch(match v1.Match, fieldPath *field.Path, upstreamNames sets.Set[string], path string) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(match.Conditions) == 0 {
		allErrs = append(allErrs, field.Required(fieldPath.Child("conditions"), "must specify at least one condition"))
	} else {
		for i, c := range match.Conditions {
			allErrs = append(allErrs, validateCondition(c, fieldPath.Child("conditions").Index(i))...)
		}
	}

	fieldCount := 0

	if match.Action != nil {
		allErrs = append(allErrs, vsv.validateAction(match.Action, fieldPath.Child("action"), upstreamNames, path, true)...)
		fieldCount++
	}

	if len(match.Splits) > 0 {
		allErrs = append(allErrs, vsv.validateSplits(match.Splits, fieldPath.Child("splits"), upstreamNames, path)...)
		fieldCount++
	}

	if fieldCount != 1 {
		allErrs = append(allErrs, field.Invalid(fieldPath, "", "must specify exactly one of `action` or `splits`"))
	}

	return allErrs
}

func validateCondition(condition v1.Condition, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	fieldCount := 0

	if condition.Header != "" {
		for _, msg := range validation.IsHTTPHeaderName(condition.Header) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("header"), condition.Header, msg))
		}
		fieldCount++
	}

	if condition.Cookie != "" {
		for _, msg := range isCookieName(condition.Cookie) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("cookie"), condition.Cookie, msg))
		}
		fieldCount++
	}

	if condition.Argument != "" {
		for _, msg := range isArgumentName(condition.Argument) {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("argument"), condition.Argument, msg))
		}
		fieldCount++
	}

	if condition.Variable != "" {
		allErrs = append(allErrs, validateVariableName(condition.Variable, fieldPath.Child("variable"))...)
		fieldCount++
	}

	if fieldCount != 1 {
		allErrs = append(allErrs, field.Invalid(fieldPath, "", "must specify exactly one of: `header`, `cookie`, `argument` or `variable`"))
	}

	for _, msg := range isValidMatchValue(condition.Value) {
		allErrs = append(allErrs, field.Invalid(fieldPath.Child("value"), condition.Value, msg))
	}

	return allErrs
}

const (
	cookieNameFmt    string = "[_A-Za-z0-9]+"
	cookieNameErrMsg string = "a valid cookie name must consist of alphanumeric characters or '_'"
)

var cookieNameRegexp = regexp.MustCompile("^" + cookieNameFmt + "$")

func isCookieName(value string) []string {
	if !cookieNameRegexp.MatchString(value) {
		return []string{validation.RegexError(cookieNameErrMsg, cookieNameFmt, "my_cookie_123")}
	}
	return nil
}

const (
	argumentNameFmt    string = "[_A-Za-z0-9]+"
	argumentNameErrMsg string = "a valid argument name must consist of alphanumeric characters or '_'"
)

var argumentNameRegexp = regexp.MustCompile("^" + argumentNameFmt + "$")

func isArgumentName(value string) []string {
	if !argumentNameRegexp.MatchString(value) {
		return []string{validation.RegexError(argumentNameErrMsg, argumentNameFmt, "argument_123")}
	}
	return nil
}

// validVariableNames includes NGINX variables allowed to be used in conditions.
// Not all NGINX variables are allowed. The full list of NGINX variables is at https://nginx.org/en/docs/varindex.html
var validVariableNames = map[string]bool{
	"$args":           true,
	"$http2":          true,
	"$https":          true,
	"$remote_addr":    true,
	"$remote_port":    true,
	"$query_string":   true,
	"$request":        true,
	"$request_body":   true,
	"$request_uri":    true,
	"$request_method": true,
	"$scheme":         true,
}

func validateVariableName(name string, fieldPath *field.Path) field.ErrorList {
	if !strings.HasPrefix(name, "$") {
		return field.ErrorList{field.Invalid(fieldPath, name, "must start with `$`")}
	}
	if _, exists := validVariableNames[name]; !exists {
		return field.ErrorList{field.Invalid(fieldPath, name, "is not allowed or is not an NGINX variable")}
	}
	return nil
}

func isValidMatchValue(value string) []string {
	if err := ValidateEscapedString(value, "value-123"); err != nil {
		return []string{err.Error()}
	}
	return nil
}

// ValidateVirtualServerRoute validates a VirtualServerRoute.
func (vsv *VirtualServerValidator) ValidateVirtualServerRoute(virtualServerRoute *v1.VirtualServerRoute) error {
	allErrs := vsv.validateVirtualServerRouteSpec(&virtualServerRoute.Spec, field.NewPath("spec"), "", "", virtualServerRoute.Namespace)
	return allErrs.ToAggregate()
}

// ValidateVirtualServerRouteForVirtualServer validates a VirtualServerRoute for a VirtualServer represented by its host and path prefix.
func (vsv *VirtualServerValidator) ValidateVirtualServerRouteForVirtualServer(virtualServerRoute *v1.VirtualServerRoute, virtualServerHost string, vsPath string) error {
	allErrs := vsv.validateVirtualServerRouteSpec(&virtualServerRoute.Spec, field.NewPath("spec"), virtualServerHost, vsPath,
		virtualServerRoute.Namespace)
	return allErrs.ToAggregate()
}

func (vsv *VirtualServerValidator) validateVirtualServerRouteSpec(spec *v1.VirtualServerRouteSpec, fieldPath *field.Path, virtualServerHost string, vsPath string,
	namespace string,
) field.ErrorList {
	allErrs := validateVirtualServerRouteHost(spec.Host, virtualServerHost, fieldPath.Child("host"))

	upstreamErrs, upstreamNames := vsv.validateUpstreams(spec.Upstreams, fieldPath.Child("upstreams"))
	allErrs = append(allErrs, upstreamErrs...)

	allErrs = append(allErrs, vsv.validateVirtualServerRouteSubroutes(spec.Subroutes, fieldPath.Child("subroutes"), upstreamNames, vsPath, namespace)...)

	return allErrs
}

func validateVirtualServerRouteHost(host string, virtualServerHost string, fieldPath *field.Path) field.ErrorList {
	allErrs := validateHost(host, fieldPath)
	if virtualServerHost != "" && host != virtualServerHost {
		msg := fmt.Sprintf("must be equal to '%s'", virtualServerHost)
		allErrs = append(allErrs, field.Invalid(fieldPath, host, msg))
	}
	return allErrs
}

func isRegexOrExactMatch(path string) bool {
	return strings.HasPrefix(path, "~") || strings.HasPrefix(path, "=")
}

func (vsv *VirtualServerValidator) validateVirtualServerRouteSubroutes(routes []v1.Route, fieldPath *field.Path, upstreamNames sets.Set[string], vsPath string, namespace string) field.ErrorList {
	allErrs := field.ErrorList{}

	allPaths := sets.Set[string]{}

	if isRegexOrExactMatch(vsPath) {
		if len(routes) != 1 {
			return append(allErrs, field.Invalid(fieldPath, "subroutes", "must have only one subroute if regex match or exact match are being used"))
		}

		idxPath := fieldPath.Index(0)
		if routes[0].Path != vsPath {
			return append(allErrs, field.Invalid(idxPath.Child("path"), routes[0].Path, "must have the same path as the referenced VirtualServer route path"))
		}

		return vsv.validateRoute(routes[0], idxPath, upstreamNames, true, namespace)
	}

	for i, r := range routes {
		idxPath := fieldPath.Index(i)

		isRouteFieldForbidden := true
		routeErrs := vsv.validateRoute(r, idxPath, upstreamNames, isRouteFieldForbidden, namespace)

		if vsPath != "" && !strings.HasPrefix(r.Path, vsPath) {
			msg := fmt.Sprintf("must start with '%s'", vsPath)
			routeErrs = append(routeErrs, field.Invalid(idxPath, r.Path, msg))
		}

		if len(routeErrs) > 0 {
			allErrs = append(allErrs, routeErrs...)
		} else if allPaths.Has(r.Path) {
			allErrs = append(allErrs, field.Duplicate(idxPath.Child("path"), r.Path))
		} else {
			allPaths.Insert(r.Path)
		}
	}

	return allErrs
}

func rejectPlusResourcesInOSS(upstream v1.Upstream, idxPath *field.Path, isPlus bool) field.ErrorList {
	if isPlus {
		return nil
	}

	allErrs := field.ErrorList{}
	if upstream.HealthCheck != nil {
		allErrs = append(allErrs, field.Forbidden(idxPath.Child("healthCheck"), "active health checks are only supported in NGINX Plus"))
	}

	if upstream.SlowStart != "" {
		allErrs = append(allErrs, field.Forbidden(idxPath.Child("slow-start"), "slow start is only supported in NGINX Plus"))
	}

	if upstream.SessionCookie != nil {
		allErrs = append(allErrs, field.Forbidden(idxPath.Child("sessionCookie"), "sticky cookies are only supported in NGINX Plus"))
	}

	if upstream.Queue != nil {
		allErrs = append(allErrs, field.Forbidden(idxPath.Child("queue"), "queue is only supported in NGINX Plus"))
	}

	if upstream.NTLM {
		allErrs = append(allErrs, field.Forbidden(idxPath.Child("ntlm"), "NTLM is only supported in NGINX Plus"))
	}

	return allErrs
}

func validateQueue(queue *v1.UpstreamQueue, fieldPath *field.Path) field.ErrorList {
	if queue == nil {
		return nil
	}
	allErrs := validateTime(queue.Timeout, fieldPath.Child("timeout"))
	if queue.Size <= 0 {
		allErrs = append(allErrs, field.Required(fieldPath.Child("size"), "must be positive"))
	}
	return allErrs
}

// isValidLabelName checks if a label name is valid.
// It performs the same validation as ValidateLabelName from k8s.io/apimachinery/pkg/apis/meta/v1/validation/validation.go.
func isValidLabelName(labelName string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for _, msg := range validation.IsQualifiedName(labelName) {
		allErrs = append(allErrs, field.Invalid(fieldPath, labelName, msg))
	}

	return allErrs
}

// validateLabels validates that a set of labels are correctly defined.
// It performs the same validation as ValidateLabels from k8s.io/apimachinery/pkg/apis/meta/v1/validation/validation.go.
func validateLabels(labels map[string]string, fieldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for labelName, labelValue := range labels {
		allErrs = append(allErrs, isValidLabelName(labelName, fieldPath)...)
		for _, msg := range validation.IsValidLabelValue(labelValue) {
			allErrs = append(allErrs, field.Invalid(fieldPath, labelValue, msg))
		}
	}

	return allErrs
}
