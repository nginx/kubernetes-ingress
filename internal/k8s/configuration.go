package k8s

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ingressKind            = "Ingress"
	virtualServerKind      = "VirtualServer"
	virtualServerRouteKind = "VirtualServerRoute"
	transportServerKind    = "TransportServer"
)

// Operation defines an operation to perform for a resource.
type Operation int

const (
	// Delete the config of the resource
	Delete Operation = iota
	// AddOrUpdate the config of the resource
	AddOrUpdate
)

// Resource represents a configuration resource.
// A Resource can be a top level configuration object:
// - Regular or Master Ingress
// - VirtualServer
// - TransportServer
type Resource interface {
	GetObjectMeta() *metav1.ObjectMeta
	GetKeyWithKind() string
	Wins(resource Resource) bool
	AddWarning(warning string)
	IsEqual(resource Resource) bool
}

func chooseObjectMetaWinner(meta1 *metav1.ObjectMeta, meta2 *metav1.ObjectMeta) bool {
	if meta1.CreationTimestamp.Equal(&meta2.CreationTimestamp) {
		return meta1.UID > meta2.UID
	}

	return meta1.CreationTimestamp.Before(&meta2.CreationTimestamp)
}

// ResourceChange represents a change of the resource that needs to be reflected in the NGINX config.
type ResourceChange struct {
	// Op is an operation that needs be performed on the resource.
	Op Operation
	// Resource is the target resource.
	Resource Resource
	// Error is the error associated with the resource.
	Error string
}

// ConfigurationProblem is a problem associated with a configuration object.
type ConfigurationProblem struct {
	// Object is a configuration object.
	Object runtime.Object
	// IsError tells if the problem is an error. If it is an error, then it is expected that the status of the object
	// will be updated to the state 'invalid'. Otherwise, the state will be 'warning'.
	IsError bool
	// Reason tells the reason. It matches the reason in the events/status of our configuration objects.
	Reason string
	// Messages gives the details about the problem. It matches the message in the events/status of our configuration objects.
	Message string
}

func compareConfigurationProblems(problem1 *ConfigurationProblem, problem2 *ConfigurationProblem) bool {
	return problem1.IsError == problem2.IsError &&
		problem1.Reason == problem2.Reason &&
		problem1.Message == problem2.Message
}

// IngressConfiguration holds an Ingress resource with its minions. It implements the Resource interface.
type IngressConfiguration struct {
	// Ingress holds a regular Ingress or a master Ingress.
	Ingress *networking.Ingress
	// IsMaster is true when the Ingress is a master.
	IsMaster bool
	// Minions contains minions if the Ingress is a master.
	Minions []*MinionConfiguration
	// ValidHosts marks the hosts of the Ingress as valid (true) or invalid (false).
	// Regular Ingress resources can have multiple hosts. It is possible that some of the hosts are taken by other
	// resources. In that case, those hosts will be marked as invalid.
	ValidHosts map[string]bool
	// Warnings includes all the warnings for the resource.
	Warnings []string
	// ChildWarnings includes the warnings of the minions. The key is the namespace/name.
	ChildWarnings map[string][]string
}

type listenerHostKey struct {
	ListenerName string
	Host         string
}

// used for sorting
func (lhk listenerHostKey) String() string {
	return fmt.Sprintf("%s|%s", lhk.ListenerName, lhk.Host)
}

// NewRegularIngressConfiguration creates an IngressConfiguration from an Ingress resource.
func NewRegularIngressConfiguration(ing *networking.Ingress) *IngressConfiguration {
	return &IngressConfiguration{
		Ingress:       ing,
		IsMaster:      false,
		ValidHosts:    make(map[string]bool),
		ChildWarnings: make(map[string][]string),
	}
}

// NewMasterIngressConfiguration creates an IngressConfiguration from a master Ingress resource.
func NewMasterIngressConfiguration(ing *networking.Ingress, minions []*MinionConfiguration, childWarnings map[string][]string) *IngressConfiguration {
	return &IngressConfiguration{
		Ingress:       ing,
		IsMaster:      true,
		Minions:       minions,
		ValidHosts:    make(map[string]bool),
		ChildWarnings: childWarnings,
	}
}

// GetObjectMeta returns the resource ObjectMeta.
func (ic *IngressConfiguration) GetObjectMeta() *metav1.ObjectMeta {
	return &ic.Ingress.ObjectMeta
}

// GetKeyWithKind returns the key of the resource with its kind. For example, Ingress/my-namespace/my-name.
func (ic *IngressConfiguration) GetKeyWithKind() string {
	key := getResourceKey(&ic.Ingress.ObjectMeta)
	return fmt.Sprintf("%s/%s", ingressKind, key)
}

// Wins tells if this resource wins over the specified resource.
func (ic *IngressConfiguration) Wins(resource Resource) bool {
	return chooseObjectMetaWinner(ic.GetObjectMeta(), resource.GetObjectMeta())
}

// AddWarning adds a warning.
func (ic *IngressConfiguration) AddWarning(warning string) {
	ic.Warnings = append(ic.Warnings, warning)
}

// IsEqual tests if the IngressConfiguration is equal to the resource.
func (ic *IngressConfiguration) IsEqual(resource Resource) bool {
	ingConfig, ok := resource.(*IngressConfiguration)
	if !ok {
		return false
	}

	if !compareObjectMetasWithAnnotations(&ic.Ingress.ObjectMeta, &ingConfig.Ingress.ObjectMeta) {
		return false
	}

	if !reflect.DeepEqual(ic.ValidHosts, ingConfig.ValidHosts) {
		return false
	}

	if ic.IsMaster != ingConfig.IsMaster {
		return false
	}

	if len(ic.Minions) != len(ingConfig.Minions) {
		return false
	}

	for i := range ic.Minions {
		if !compareObjectMetasWithAnnotations(&ic.Minions[i].Ingress.ObjectMeta, &ingConfig.Minions[i].Ingress.ObjectMeta) {
			return false
		}
	}

	return true
}

// MinionConfiguration holds a Minion resource.
type MinionConfiguration struct {
	// Ingress is the Ingress behind a minion.
	Ingress *networking.Ingress
	// ValidPaths marks the paths of the Ingress as valid (true) or invalid (false).
	// Minion Ingress resources can have multiple paths. It is possible that some of the paths are taken by other
	// Minions. In that case, those paths will be marked as invalid.
	ValidPaths map[string]bool
}

// NewMinionConfiguration creates a new MinionConfiguration.
func NewMinionConfiguration(ing *networking.Ingress) *MinionConfiguration {
	return &MinionConfiguration{
		Ingress:    ing,
		ValidPaths: make(map[string]bool),
	}
}

// VirtualServerConfiguration holds a VirtualServer along with its VirtualServerRoutes.
type VirtualServerConfiguration struct {
	VirtualServer       *conf_v1.VirtualServer
	VirtualServerRoutes []*conf_v1.VirtualServerRoute
	Warnings            []string
	HTTPPort            int
	HTTPSPort           int
	HTTPIPv4            string
	HTTPIPv6            string
	HTTPSIPv4           string
	HTTPSIPv6           string
}

// NewVirtualServerConfiguration creates a VirtualServerConfiguration.
func NewVirtualServerConfiguration(vs *conf_v1.VirtualServer, vsrs []*conf_v1.VirtualServerRoute, warnings []string) *VirtualServerConfiguration {
	return &VirtualServerConfiguration{
		VirtualServer:       vs,
		VirtualServerRoutes: vsrs,
		Warnings:            warnings,
	}
}

// GetObjectMeta returns the resource ObjectMeta.
func (vsc *VirtualServerConfiguration) GetObjectMeta() *metav1.ObjectMeta {
	return &vsc.VirtualServer.ObjectMeta
}

// GetKeyWithKind returns the key of the resource with its kind. For example, VirtualServer/my-namespace/my-name.
func (vsc *VirtualServerConfiguration) GetKeyWithKind() string {
	key := getResourceKey(&vsc.VirtualServer.ObjectMeta)
	return fmt.Sprintf("%s/%s", virtualServerKind, key)
}

// Wins tells if this resource wins over the specified resource.
// It is used to determine which resource should win over a host.
func (vsc *VirtualServerConfiguration) Wins(resource Resource) bool {
	return chooseObjectMetaWinner(vsc.GetObjectMeta(), resource.GetObjectMeta())
}

// AddWarning adds a warning.
func (vsc *VirtualServerConfiguration) AddWarning(warning string) {
	vsc.Warnings = append(vsc.Warnings, warning)
}

// IsEqual tests if the VirtualServerConfiguration is equal to the resource.
func (vsc *VirtualServerConfiguration) IsEqual(resource Resource) bool {
	vsConfig, ok := resource.(*VirtualServerConfiguration)
	if !ok {
		return false
	}

	if !compareObjectMetas(&vsc.VirtualServer.ObjectMeta, &vsConfig.VirtualServer.ObjectMeta) {
		return false
	}

	if len(vsc.VirtualServerRoutes) != len(vsConfig.VirtualServerRoutes) {
		return false
	}

	for i := range vsc.VirtualServerRoutes {
		if !compareObjectMetas(&vsc.VirtualServerRoutes[i].ObjectMeta, &vsConfig.VirtualServerRoutes[i].ObjectMeta) {
			return false
		}
	}

	return true
}

// TransportServerConfiguration holds a TransportServer resource.
type TransportServerConfiguration struct {
	ListenerPort    int
	IPv4            string
	IPv6            string
	TransportServer *conf_v1.TransportServer
	Warnings        []string
}

// NewTransportServerConfiguration creates a new TransportServerConfiguration.
func NewTransportServerConfiguration(ts *conf_v1.TransportServer) *TransportServerConfiguration {
	return &TransportServerConfiguration{
		TransportServer: ts,
	}
}

// GetObjectMeta returns the resource ObjectMeta.
func (tsc *TransportServerConfiguration) GetObjectMeta() *metav1.ObjectMeta {
	return &tsc.TransportServer.ObjectMeta
}

// GetKeyWithKind returns the key of the resource with its kind. For example, TransportServer/my-namespace/my-name.
func (tsc *TransportServerConfiguration) GetKeyWithKind() string {
	key := getResourceKey(&tsc.TransportServer.ObjectMeta)
	return fmt.Sprintf("%s/%s", transportServerKind, key)
}

// Wins tells if this resource wins over the specified resource.
// It is used to determine which resource should win over a host or port.
func (tsc *TransportServerConfiguration) Wins(resource Resource) bool {
	return chooseObjectMetaWinner(tsc.GetObjectMeta(), resource.GetObjectMeta())
}

// AddWarning adds a warning.
func (tsc *TransportServerConfiguration) AddWarning(warning string) {
	tsc.Warnings = append(tsc.Warnings, warning)
}

// IsEqual tests if the TransportServerConfiguration is equal to the resource.
func (tsc *TransportServerConfiguration) IsEqual(resource Resource) bool {
	tsConfig, ok := resource.(*TransportServerConfiguration)
	if !ok {
		return false
	}

	return compareObjectMetas(tsc.GetObjectMeta(), resource.GetObjectMeta()) && tsc.ListenerPort == tsConfig.ListenerPort
}

func compareObjectMetas(meta1 *metav1.ObjectMeta, meta2 *metav1.ObjectMeta) bool {
	return meta1.Namespace == meta2.Namespace &&
		meta1.Name == meta2.Name &&
		meta1.Generation == meta2.Generation
}

func compareObjectMetasWithAnnotations(meta1 *metav1.ObjectMeta, meta2 *metav1.ObjectMeta) bool {
	return compareObjectMetas(meta1, meta2) && reflect.DeepEqual(meta1.Annotations, meta2.Annotations)
}

// TransportServerMetrics holds metrics about TransportServer resources
type TransportServerMetrics struct {
	TotalTLSPassthrough int
	TotalTCP            int
	TotalUDP            int
}

// Configuration represents the configuration of the Ingress Controller - a collection of configuration objects
// (Ingresses, VirtualServers, VirtualServerRoutes) ready to be transformed into NGINX config.
// It holds the latest valid state of those objects.
// The IC needs to ensure that at any point in time the NGINX config on the filesystem reflects the state
// of the objects in the Configuration.
type Configuration struct {
	hosts         map[string]Resource
	listenerHosts map[listenerHostKey]*TransportServerConfiguration
	listenerMap   map[string]conf_v1.Listener

	// only valid resources with the matching IngressClass are stored
	ingresses           map[string]*networking.Ingress
	virtualServers      map[string]*conf_v1.VirtualServer
	virtualServerRoutes map[string]*conf_v1.VirtualServerRoute
	transportServers    map[string]*conf_v1.TransportServer

	globalConfiguration *conf_v1.GlobalConfiguration

	hostProblems     map[string]ConfigurationProblem
	listenerProblems map[string]ConfigurationProblem

	hasCorrectIngressClass       func(interface{}) bool
	virtualServerValidator       *validation.VirtualServerValidator
	globalConfigurationValidator *validation.GlobalConfigurationValidator
	transportServerValidator     *validation.TransportServerValidator

	secretReferenceChecker     *secretReferenceChecker
	serviceReferenceChecker    *serviceReferenceChecker
	endpointReferenceChecker   *serviceReferenceChecker
	policyReferenceChecker     *policyReferenceChecker
	appPolicyReferenceChecker  *appProtectResourceReferenceChecker
	appLogConfReferenceChecker *appProtectResourceReferenceChecker
	appDosProtectedChecker     *dosResourceReferenceChecker

	isPlus                  bool
	appProtectEnabled       bool
	appProtectDosEnabled    bool
	internalRoutesEnabled   bool
	isTLSPassthroughEnabled bool
	snippetsEnabled         bool
	isCertManagerEnabled    bool
	isIPV6Disabled          bool

	lock sync.RWMutex
}

// NewConfiguration creates a new Configuration.
func NewConfiguration(
	hasCorrectIngressClass func(interface{}) bool,
	isPlus bool,
	appProtectEnabled bool,
	appProtectDosEnabled bool,
	internalRoutesEnabled bool,
	virtualServerValidator *validation.VirtualServerValidator,
	globalConfigurationValidator *validation.GlobalConfigurationValidator,
	transportServerValidator *validation.TransportServerValidator,
	isTLSPassthroughEnabled bool,
	snippetsEnabled bool,
	isCertManagerEnabled bool,
	isIPV6Disabled bool,
) *Configuration {
	return &Configuration{
		hosts:                        make(map[string]Resource),
		listenerHosts:                make(map[listenerHostKey]*TransportServerConfiguration),
		ingresses:                    make(map[string]*networking.Ingress),
		virtualServers:               make(map[string]*conf_v1.VirtualServer),
		virtualServerRoutes:          make(map[string]*conf_v1.VirtualServerRoute),
		transportServers:             make(map[string]*conf_v1.TransportServer),
		hostProblems:                 make(map[string]ConfigurationProblem),
		hasCorrectIngressClass:       hasCorrectIngressClass,
		virtualServerValidator:       virtualServerValidator,
		globalConfigurationValidator: globalConfigurationValidator,
		transportServerValidator:     transportServerValidator,
		secretReferenceChecker:       newSecretReferenceChecker(isPlus),
		serviceReferenceChecker:      newServiceReferenceChecker(false),
		endpointReferenceChecker:     newServiceReferenceChecker(true),
		policyReferenceChecker:       newPolicyReferenceChecker(),
		appPolicyReferenceChecker:    newAppProtectResourceReferenceChecker(configs.AppProtectPolicyAnnotation),
		appLogConfReferenceChecker:   newAppProtectResourceReferenceChecker(configs.AppProtectLogConfAnnotation),
		appDosProtectedChecker:       newDosResourceReferenceChecker(configs.AppProtectDosProtectedAnnotation),
		isPlus:                       isPlus,
		appProtectEnabled:            appProtectEnabled,
		appProtectDosEnabled:         appProtectDosEnabled,
		internalRoutesEnabled:        internalRoutesEnabled,
		isTLSPassthroughEnabled:      isTLSPassthroughEnabled,
		snippetsEnabled:              snippetsEnabled,
		isCertManagerEnabled:         isCertManagerEnabled,
		isIPV6Disabled:               isIPV6Disabled,
	}
}

// AddOrUpdateIngress adds or updates the Ingress resource.
func (c *Configuration) AddOrUpdateIngress(ing *networking.Ingress) ([]ResourceChange, []ConfigurationProblem) {
	c.lock.Lock()
	defer c.lock.Unlock()

	key := getResourceKey(&ing.ObjectMeta)
	var validationError error

	if !c.hasCorrectIngressClass(ing) {
		delete(c.ingresses, key)
	} else {
		validationError = validateIngress(ing, c.isPlus, c.appProtectEnabled, c.appProtectDosEnabled, c.internalRoutesEnabled, c.snippetsEnabled).ToAggregate()
		if validationError != nil {
			delete(c.ingresses, key)
		} else {
			c.ingresses[key] = ing
		}
	}

	changes, problems := c.rebuildHosts()

	if validationError != nil {
		// If the invalid resource has any active hosts, rebuildHosts will create a change
		// to remove the resource.
		// Here we add the validationErr to that change.
		keyWithKind := getResourceKeyWithKind(ingressKind, &ing.ObjectMeta)
		for i := range changes {
			k := changes[i].Resource.GetKeyWithKind()

			if k == keyWithKind {
				changes[i].Error = validationError.Error()
				return changes, problems
			}
		}

		// On the other hand, the invalid resource might not have any active hosts.
		// Or the resource was invalid before and is still invalid (in some different way).
		// In those cases,  rebuildHosts will create no change for that resource.
		// To make sure the validationErr is reported to the user, we create a problem.
		p := ConfigurationProblem{
			Object:  ing,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: validationError.Error(),
		}
		problems = append(problems, p)
	}

	return changes, problems
}

// DeleteIngress deletes an Ingress resource by the key.
func (c *Configuration) DeleteIngress(key string) ([]ResourceChange, []ConfigurationProblem) {
	c.lock.Lock()
	defer c.lock.Unlock()

	_, exists := c.ingresses[key]
	if !exists {
		return nil, nil
	}

	delete(c.ingresses, key)

	return c.rebuildHosts()
}

// AddOrUpdateVirtualServer adds or updates the VirtualServer resource.
func (c *Configuration) AddOrUpdateVirtualServer(vs *conf_v1.VirtualServer) ([]ResourceChange, []ConfigurationProblem) {
	c.lock.Lock()
	defer c.lock.Unlock()

	key := getResourceKey(&vs.ObjectMeta)
	var validationError error

	if !c.hasCorrectIngressClass(vs) {
		delete(c.virtualServers, key)
	} else {
		validationError = c.virtualServerValidator.ValidateVirtualServer(vs)
		if validationError != nil {
			delete(c.virtualServers, key)
		} else {
			c.virtualServers[key] = vs
		}
	}

	changes, problems := c.rebuildHosts()

	if validationError != nil {
		// If the invalid resource has an active host, rebuildHosts will create a change
		// to remove the resource.
		// Here we add the validationErr to that change.
		kind := getResourceKeyWithKind(virtualServerKind, &vs.ObjectMeta)
		for i := range changes {
			k := changes[i].Resource.GetKeyWithKind()

			if k == kind {
				changes[i].Error = validationError.Error()
				return changes, problems
			}
		}

		// On the other hand, the invalid resource might not have any active host.
		// Or the resource was invalid before and is still invalid (in some different way).
		// In those cases,  rebuildHosts will create no change for that resource.
		// To make sure the validationErr is reported to the user, we create a problem.
		p := ConfigurationProblem{
			Object:  vs,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: fmt.Sprintf("VirtualServer %s was rejected with error: %s", getResourceKey(&vs.ObjectMeta), validationError.Error()),
		}
		problems = append(problems, p)
	}

	return changes, problems
}

// DeleteVirtualServer deletes a VirtualServerResource by the key.
func (c *Configuration) DeleteVirtualServer(key string) ([]ResourceChange, []ConfigurationProblem) {
	c.lock.Lock()
	defer c.lock.Unlock()

	_, exists := c.virtualServers[key]
	if !exists {
		return nil, nil
	}

	delete(c.virtualServers, key)

	return c.rebuildHosts()
}

// AddOrUpdateVirtualServerRoute adds or updates the VirtualServerRoute.
func (c *Configuration) AddOrUpdateVirtualServerRoute(vsr *conf_v1.VirtualServerRoute) ([]ResourceChange, []ConfigurationProblem) {
	c.lock.Lock()
	defer c.lock.Unlock()

	key := getResourceKey(&vsr.ObjectMeta)
	var validationError error

	if !c.hasCorrectIngressClass(vsr) {
		delete(c.virtualServerRoutes, key)
	} else {
		validationError = c.virtualServerValidator.ValidateVirtualServerRoute(vsr)
		if validationError != nil {
			delete(c.virtualServerRoutes, key)
		} else {
			c.virtualServerRoutes[key] = vsr
		}
	}

	changes, problems := c.rebuildHosts()

	if validationError != nil {
		p := ConfigurationProblem{
			Object:  vsr,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: fmt.Sprintf("VirtualServerRoute %s was rejected with error: %s", getResourceKey(&vsr.ObjectMeta), validationError.Error()),
		}
		problems = append(problems, p)
	}

	return changes, problems
}

// DeleteVirtualServerRoute deletes a VirtualServerRoute by the key.
func (c *Configuration) DeleteVirtualServerRoute(key string) ([]ResourceChange, []ConfigurationProblem) {
	c.lock.Lock()
	defer c.lock.Unlock()

	_, exists := c.virtualServerRoutes[key]
	if !exists {
		return nil, nil
	}

	delete(c.virtualServerRoutes, key)

	return c.rebuildHosts()
}

// AddOrUpdateGlobalConfiguration adds or updates the GlobalConfiguration.
func (c *Configuration) AddOrUpdateGlobalConfiguration(gc *conf_v1.GlobalConfiguration) ([]ResourceChange, []ConfigurationProblem, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	var changes []ResourceChange
	var problems []ConfigurationProblem

	validationErr := c.globalConfigurationValidator.ValidateGlobalConfiguration(gc)

	c.globalConfiguration = gc
	c.setGlobalConfigListenerMap()

	listenerChanges, listenerProblems := c.rebuildListenerHosts()

	changes = append(changes, listenerChanges...)
	problems = append(problems, listenerProblems...)

	hostChanges, hostProblems := c.rebuildHosts()
	changes = append(changes, hostChanges...)
	problems = append(problems, hostProblems...)

	return changes, problems, validationErr
}

// DeleteGlobalConfiguration deletes GlobalConfiguration.
func (c *Configuration) DeleteGlobalConfiguration() ([]ResourceChange, []ConfigurationProblem) {
	c.lock.Lock()
	defer c.lock.Unlock()

	var changes []ResourceChange
	var problems []ConfigurationProblem

	c.globalConfiguration = nil
	c.setGlobalConfigListenerMap()
	listenerChanges, listenerProblems := c.rebuildListenerHosts()
	changes = append(changes, listenerChanges...)
	problems = append(problems, listenerProblems...)

	hostChanges, hostProblems := c.rebuildHosts()
	changes = append(changes, hostChanges...)
	problems = append(problems, hostProblems...)

	return changes, problems
}

// GetGlobalConfiguration returns the current GlobalConfiguration.
func (c *Configuration) GetGlobalConfiguration() *conf_v1.GlobalConfiguration {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.globalConfiguration
}

// AddOrUpdateTransportServer adds or updates the TransportServer.
func (c *Configuration) AddOrUpdateTransportServer(ts *conf_v1.TransportServer) ([]ResourceChange, []ConfigurationProblem) {
	c.lock.Lock()
	defer c.lock.Unlock()

	key := getResourceKey(&ts.ObjectMeta)
	var validationErr error

	if !c.hasCorrectIngressClass(ts) {
		delete(c.transportServers, key)
	} else {
		validationErr = c.transportServerValidator.ValidateTransportServer(ts)
		if validationErr != nil {
			delete(c.transportServers, key)
		} else {
			c.transportServers[key] = ts
		}
	}

	changes, problems := c.rebuildListenerHosts()

	if c.isTLSPassthroughEnabled {
		hostChanges, hostProblems := c.rebuildHosts()

		changes = append(changes, hostChanges...)
		problems = append(problems, hostProblems...)
	}

	if validationErr != nil {
		// If the invalid resource has an active host/listener, rebuildHosts/rebuildListenerHosts will create a change
		// to remove the resource.
		// Here we add the validationErr to that change.
		kind := getResourceKeyWithKind(transportServerKind, &ts.ObjectMeta)
		for i := range changes {
			k := changes[i].Resource.GetKeyWithKind()

			if k == kind {
				changes[i].Error = validationErr.Error()
				return changes, problems
			}
		}

		// On the other hand, the invalid resource might not have any active host/listener.
		// Or the resource was invalid before and is still invalid (in some different way).
		// In those cases,  rebuildHosts/rebuildListenerHosts will create no change for that resource.
		// To make sure the validationErr is reported to the user, we create a problem.
		p := ConfigurationProblem{
			Object:  ts,
			IsError: true,
			Reason:  nl.EventReasonRejected,
			Message: fmt.Sprintf("TransportServer %s was rejected with error: %s", getResourceKey(&ts.ObjectMeta), validationErr.Error()),
		}
		problems = append(problems, p)
	}

	return changes, problems
}

// DeleteTransportServer deletes a TransportServer by the key.
func (c *Configuration) DeleteTransportServer(key string) ([]ResourceChange, []ConfigurationProblem) {
	c.lock.Lock()
	defer c.lock.Unlock()

	_, exists := c.transportServers[key]
	if !exists {
		return nil, nil
	}

	delete(c.transportServers, key)

	changes, problems := c.rebuildListenerHosts()

	if c.isTLSPassthroughEnabled {
		hostChanges, hostProblems := c.rebuildHosts()

		changes = append(changes, hostChanges...)
		problems = append(problems, hostProblems...)
	}

	return changes, problems
}

func (c *Configuration) rebuildListenerHosts() ([]ResourceChange, []ConfigurationProblem) {
	newListenerHosts, newTSConfigs := c.buildListenerHostsAndTSConfigurations()

	removedListenerHosts, updatedListenerHosts, addedListenerHosts := detectChangesInListenerHosts(c.listenerHosts, newListenerHosts)
	changes := createResourceChangesForListeners(removedListenerHosts, updatedListenerHosts, addedListenerHosts, c.listenerHosts, newListenerHosts)

	c.listenerHosts = newListenerHosts

	changes = squashResourceChanges(changes)

	// Note that the change will not refer to the latest version, if the TransportServerConfiguration is being removed.
	// However, referring to the latest version is necessary so that the resource latest Warnings are reported and not lost.
	// So here we make sure that changes always refer to the latest version of TransportServerConfigurations.
	for i := range changes {
		key := changes[i].Resource.GetKeyWithKind()
		if r, exists := newTSConfigs[key]; exists {
			changes[i].Resource = r
		}
	}

	newProblems := make(map[string]ConfigurationProblem)

	c.addProblemsForTSConfigsWithoutActiveListener(newTSConfigs, newProblems)

	newOrUpdatedProblems := detectChangesInProblems(newProblems, c.listenerProblems)

	// safe to update problems
	c.listenerProblems = newProblems

	return changes, newOrUpdatedProblems
}

func (c *Configuration) buildListenerHostsAndTSConfigurations() (map[listenerHostKey]*TransportServerConfiguration, map[string]*TransportServerConfiguration) {
	newListenerHosts := make(map[listenerHostKey]*TransportServerConfiguration)
	newTSConfigs := make(map[string]*TransportServerConfiguration)

	for key, ts := range c.transportServers {
		if ts.Spec.Listener.Protocol == conf_v1.TLSPassthroughListenerProtocol {
			continue
		}
		tsc := NewTransportServerConfiguration(ts)
		newTSConfigs[key] = tsc

		if c.globalConfiguration == nil {
			continue
		}

		found := false
		var listener conf_v1.Listener
		for _, l := range c.globalConfiguration.Spec.Listeners {
			if ts.Spec.Listener.Name == l.Name && ts.Spec.Listener.Protocol == l.Protocol {
				listener = l
				found = true
				break
			}
		}

		if !found {
			continue
		}

		tsc.ListenerPort = listener.Port
		tsc.IPv4 = listener.IPv4
		tsc.IPv6 = listener.IPv6

		host := ts.Spec.Host
		listenerKey := listenerHostKey{ListenerName: listener.Name, Host: host}

		holder, exists := newListenerHosts[listenerKey]
		if !exists {
			newListenerHosts[listenerKey] = tsc
			continue
		}

		// another TransportServer exists with the same listener and host
		warning := fmt.Sprintf("listener %s and host %s are taken by another resource", listener.Name, host)

		if !holder.Wins(tsc) {
			holder.AddWarning(warning)
			newListenerHosts[listenerKey] = tsc
		} else {
			tsc.AddWarning(warning)
		}
	}

	return newListenerHosts, newTSConfigs
}

func (c *Configuration) buildListenersForVSConfiguration(vsc *VirtualServerConfiguration) {
	vs := vsc.VirtualServer
	if vs.Spec.Listener == nil || c.globalConfiguration == nil {
		return
	}

	assignListener := func(listenerName string, isSSL bool, port *int, ipv4 *string, ipv6 *string) {
		if gcListener, ok := c.listenerMap[listenerName]; ok && gcListener.Protocol == conf_v1.HTTPProtocol && gcListener.Ssl == isSSL {
			*port = gcListener.Port
			*ipv4 = gcListener.IPv4
			*ipv6 = gcListener.IPv6
		}
	}

	assignListener(vs.Spec.Listener.HTTP, false, &vsc.HTTPPort, &vsc.HTTPIPv4, &vsc.HTTPIPv6)
	assignListener(vs.Spec.Listener.HTTPS, true, &vsc.HTTPSPort, &vsc.HTTPSIPv4, &vsc.HTTPSIPv6)
}

// GetResources returns all configuration resources.
func (c *Configuration) GetResources() []Resource {
	return c.GetResourcesWithFilter(resourceFilter{
		Ingresses:        true,
		VirtualServers:   true,
		TransportServers: true,
	})
}

type resourceFilter struct {
	Ingresses        bool
	VirtualServers   bool
	TransportServers bool
}

// GetResourcesWithFilter returns resources using the filter.
func (c *Configuration) GetResourcesWithFilter(filter resourceFilter) []Resource {
	c.lock.RLock()
	defer c.lock.RUnlock()

	resources := make(map[string]Resource)

	for _, r := range c.hosts {
		switch r.(type) {
		case *IngressConfiguration:
			if filter.Ingresses {
				resources[r.GetKeyWithKind()] = r
			}
		case *VirtualServerConfiguration:
			if filter.VirtualServers {
				resources[r.GetKeyWithKind()] = r
			}
		case *TransportServerConfiguration:
			if filter.TransportServers {
				resources[r.GetKeyWithKind()] = r
			}
		}
	}

	if filter.TransportServers {
		for _, r := range c.listenerHosts {
			resources[r.GetKeyWithKind()] = r
		}
	}

	var result []Resource
	for _, key := range getSortedResourceKeys(resources) {
		result = append(result, resources[key])
	}

	return result
}

// FindResourcesForService finds resources that reference the specified service.
func (c *Configuration) FindResourcesForService(svcNamespace string, svcName string) []Resource {
	return c.findResourcesForResourceReference(svcNamespace, svcName, c.serviceReferenceChecker)
}

// FindResourcesForEndpoints finds resources that reference the specified endpoints.
func (c *Configuration) FindResourcesForEndpoints(endpointsNamespace string, endpointsName string) []Resource {
	// Resources reference not endpoints but the corresponding service, which has the same namespace and name
	return c.findResourcesForResourceReference(endpointsNamespace, endpointsName, c.endpointReferenceChecker)
}

// FindResourcesForSecret finds resources that reference the specified secret.
func (c *Configuration) FindResourcesForSecret(secretNamespace string, secretName string) []Resource {
	return c.findResourcesForResourceReference(secretNamespace, secretName, c.secretReferenceChecker)
}

// FindResourcesForPolicy finds resources that reference the specified policy.
func (c *Configuration) FindResourcesForPolicy(policyNamespace string, policyName string) []Resource {
	return c.findResourcesForResourceReference(policyNamespace, policyName, c.policyReferenceChecker)
}

// FindResourcesForAppProtectPolicyAnnotation finds resources that reference the specified AppProtect policy via annotation.
func (c *Configuration) FindResourcesForAppProtectPolicyAnnotation(policyNamespace string, policyName string) []Resource {
	return c.findResourcesForResourceReference(policyNamespace, policyName, c.appPolicyReferenceChecker)
}

// FindResourcesForAppProtectLogConfAnnotation finds resources that reference the specified AppProtect LogConf.
func (c *Configuration) FindResourcesForAppProtectLogConfAnnotation(logConfNamespace string, logConfName string) []Resource {
	return c.findResourcesForResourceReference(logConfNamespace, logConfName, c.appLogConfReferenceChecker)
}

// FindResourcesForAppProtectDosProtected finds resources that reference the specified AppProtectDos DosLogConf.
func (c *Configuration) FindResourcesForAppProtectDosProtected(namespace string, name string) []Resource {
	return c.findResourcesForResourceReference(namespace, name, c.appDosProtectedChecker)
}

// FindIngressesWithRatelimitScaling finds ingresses that use rate limit scaling
func (c *Configuration) FindIngressesWithRatelimitScaling(svcNamespace string) []Resource {
	return c.findResourcesForResourceReference(svcNamespace, "", &ratelimitScalingAnnotationChecker{})
}

func (c *Configuration) findResourcesForResourceReference(namespace string, name string, checker resourceReferenceChecker) []Resource {
	c.lock.RLock()
	defer c.lock.RUnlock()

	var result []Resource

	for _, h := range getSortedResourceKeys(c.hosts) {
		r := c.hosts[h]

		switch impl := r.(type) {
		case *IngressConfiguration:
			if checker.IsReferencedByIngress(namespace, name, impl.Ingress) {
				result = append(result, r)
				continue
			}

			for _, fm := range impl.Minions {
				if checker.IsReferencedByMinion(namespace, name, fm.Ingress) {
					result = append(result, r)
					break
				}
			}
		case *VirtualServerConfiguration:
			if checker.IsReferencedByVirtualServer(namespace, name, impl.VirtualServer) {
				result = append(result, r)
				continue
			}

			for _, vsr := range impl.VirtualServerRoutes {
				if checker.IsReferencedByVirtualServerRoute(namespace, name, vsr) {
					result = append(result, r)
					break
				}
			}
		case *TransportServerConfiguration:
			if checker.IsReferencedByTransportServer(namespace, name, impl.TransportServer) {
				result = append(result, r)
				continue
			}
		}
	}

	for _, lh := range getSortedListenerHostKeys(c.listenerHosts) {
		tsConfig := c.listenerHosts[lh]

		if checker.IsReferencedByTransportServer(namespace, name, tsConfig.TransportServer) {
			result = append(result, tsConfig)
			continue
		}
	}

	return result
}

func getResourceKey(meta *metav1.ObjectMeta) string {
	return fmt.Sprintf("%s/%s", meta.Namespace, meta.Name)
}

// rebuildHosts rebuilds the Configuration and returns the changes to it and the new problems.
func (c *Configuration) rebuildHosts() ([]ResourceChange, []ConfigurationProblem) {
	newHosts, newResources := c.buildHostsAndResources()

	updateActiveHostsForIngresses(newHosts, newResources)

	removedHosts, updatedHosts, addedHosts := detectChangesInHosts(c.hosts, newHosts)
	changes := createResourceChangesForHosts(removedHosts, updatedHosts, addedHosts, c.hosts, newHosts)

	// safe to update hosts
	c.hosts = newHosts

	changes = squashResourceChanges(changes)

	// Note that the change will not refer to the latest version, if the resource is being removed.
	// However, referring to the latest version is necessary so that the resource latest Warnings are reported and not lost.
	// So here we make sure that changes always refer to the latest version of resources.
	for i := range changes {
		key := changes[i].Resource.GetKeyWithKind()
		if r, exists := newResources[key]; exists {
			changes[i].Resource = r
		}
	}
	newProblems := make(map[string]ConfigurationProblem)

	c.addProblemsForResourcesWithoutActiveHost(newResources, newProblems)
	c.addProblemsForOrphanMinions(newProblems)
	c.addProblemsForOrphanOrIgnoredVsrs(newProblems)
	c.addWarningsForVirtualServersWithMissConfiguredListeners(newResources)

	newOrUpdatedProblems := detectChangesInProblems(newProblems, c.hostProblems)

	// safe to update problems
	c.hostProblems = newProblems

	return changes, newOrUpdatedProblems
}

func updateActiveHostsForIngresses(hosts map[string]Resource, resources map[string]Resource) {
	for _, r := range resources {
		ingConfig, ok := r.(*IngressConfiguration)
		if !ok {
			continue
		}

		for _, rule := range ingConfig.Ingress.Spec.Rules {
			res := hosts[rule.Host]
			ingConfig.ValidHosts[rule.Host] = res.GetKeyWithKind() == r.GetKeyWithKind()
		}
	}
}

func detectChangesInProblems(newProblems map[string]ConfigurationProblem, oldProblems map[string]ConfigurationProblem) []ConfigurationProblem {
	var result []ConfigurationProblem

	for _, key := range getSortedProblemKeys(newProblems) {
		newP := newProblems[key]

		oldP, exists := oldProblems[key]
		if !exists {
			result = append(result, newP)
			continue
		}

		if !compareConfigurationProblems(&newP, &oldP) {
			result = append(result, newP)
		}
	}

	return result
}

func (c *Configuration) addProblemsForTSConfigsWithoutActiveListener(
	tsConfigs map[string]*TransportServerConfiguration,
	problems map[string]ConfigurationProblem,
) {
	for _, tsc := range tsConfigs {
		listenerName := tsc.TransportServer.Spec.Listener.Name
		host := tsc.TransportServer.Spec.Host
		hostDescription := "empty host"
		if host != "" {
			hostDescription = host
		}
		key := listenerHostKey{ListenerName: listenerName, Host: host}
		holder, exists := c.listenerHosts[key]
		if !exists {
			p := ConfigurationProblem{
				Object:  tsc.TransportServer,
				IsError: false,
				Reason:  nl.EventReasonRejected,
				Message: fmt.Sprintf("Listener %s doesn't exist", listenerName),
			}
			problems[tsc.GetKeyWithKind()] = p
			continue
		}

		if !tsc.IsEqual(holder) {
			p := ConfigurationProblem{
				Object:  tsc.TransportServer,
				IsError: false,
				Reason:  nl.EventReasonRejected,
				Message: fmt.Sprintf("Listener %s with host %s is taken by another resource", listenerName, hostDescription),
			}
			problems[tsc.GetKeyWithKind()] = p
		}
	}
}

func (c *Configuration) addProblemsForResourcesWithoutActiveHost(resources map[string]Resource, problems map[string]ConfigurationProblem) {
	for _, r := range resources {
		switch impl := r.(type) {
		case *IngressConfiguration:
			atLeastOneValidHost := false
			for _, v := range impl.ValidHosts {
				if v {
					atLeastOneValidHost = true
					break
				}
			}
			if !atLeastOneValidHost {
				p := ConfigurationProblem{
					Object:  impl.Ingress,
					IsError: false,
					Reason:  nl.EventReasonRejected,
					Message: "All hosts are taken by other resources",
				}
				problems[r.GetKeyWithKind()] = p
			}
		case *VirtualServerConfiguration:
			res := c.hosts[impl.VirtualServer.Spec.Host]

			if res.GetKeyWithKind() != r.GetKeyWithKind() {
				p := ConfigurationProblem{
					Object:  impl.VirtualServer,
					IsError: false,
					Reason:  nl.EventReasonRejected,
					Message: "Host is taken by another resource",
				}
				problems[r.GetKeyWithKind()] = p
			}
		case *TransportServerConfiguration:
			res := c.hosts[impl.TransportServer.Spec.Host]

			if res.GetKeyWithKind() != r.GetKeyWithKind() {
				p := ConfigurationProblem{
					Object:  impl.TransportServer,
					IsError: false,
					Reason:  nl.EventReasonRejected,
					Message: "Host is taken by another resource",
				}
				problems[r.GetKeyWithKind()] = p
			}
		}
	}
}

func (c *Configuration) addWarningsForVirtualServersWithMissConfiguredListeners(resources map[string]Resource) {
	for _, r := range resources {
		vsc, ok := r.(*VirtualServerConfiguration)
		if !ok {
			continue
		}
		if vsc.VirtualServer.Spec.Listener != nil {
			if c.globalConfiguration == nil {
				warningMsg := "Listeners defined, but no GlobalConfiguration is deployed"
				c.hosts[vsc.VirtualServer.Spec.Host].AddWarning(warningMsg)
				continue
			}

			if !c.isListenerInCorrectBlock(vsc.VirtualServer.Spec.Listener.HTTP, false) {
				warningMsg := fmt.Sprintf("Listener %s can't be use in `listener.http` context as SSL is enabled for that listener.",
					vsc.VirtualServer.Spec.Listener.HTTP)
				c.hosts[vsc.VirtualServer.Spec.Host].AddWarning(warningMsg)
				continue
			}

			if !c.isListenerInCorrectBlock(vsc.VirtualServer.Spec.Listener.HTTPS, true) {
				warningMsg := fmt.Sprintf("Listener %s can't be use in `listener.https` context as SSL is not enabled for that listener.",
					vsc.VirtualServer.Spec.Listener.HTTPS)
				c.hosts[vsc.VirtualServer.Spec.Host].AddWarning(warningMsg)
				continue
			}

			if vsc.VirtualServer.Spec.Listener.HTTP != "" {
				if _, exists := c.listenerMap[vsc.VirtualServer.Spec.Listener.HTTP]; !exists {
					warningMsg := fmt.Sprintf("Listener %s is not defined in GlobalConfiguration",
						vsc.VirtualServer.Spec.Listener.HTTP)
					c.hosts[vsc.VirtualServer.Spec.Host].AddWarning(warningMsg)
					continue
				}
			}

			if vsc.VirtualServer.Spec.Listener.HTTPS != "" {
				if _, exists := c.listenerMap[vsc.VirtualServer.Spec.Listener.HTTPS]; !exists {
					warningMsg := fmt.Sprintf("Listener %s is not defined in GlobalConfiguration",
						vsc.VirtualServer.Spec.Listener.HTTPS)
					c.hosts[vsc.VirtualServer.Spec.Host].AddWarning(warningMsg)
					continue
				}
			}
		}
	}
}

func (c *Configuration) isListenerInCorrectBlock(listenerName string, expectedSsl bool) bool {
	if listener, ok := c.listenerMap[listenerName]; listener.Ssl != expectedSsl && ok {
		return false
	}
	return true
}

func (c *Configuration) addProblemsForOrphanMinions(problems map[string]ConfigurationProblem) {
	for _, key := range getSortedIngressKeys(c.ingresses) {
		ing := c.ingresses[key]

		if !isMinion(ing) {
			continue
		}

		r, exists := c.hosts[ing.Spec.Rules[0].Host]
		ingressConf, ok := r.(*IngressConfiguration)

		if !exists || !ok || !ingressConf.IsMaster {
			p := ConfigurationProblem{
				Object:  ing,
				IsError: false,
				Reason:  nl.EventReasonNoIngressMasterFound,
				Message: "Ingress master is invalid or doesn't exist",
			}
			k := getResourceKeyWithKind(ingressKind, &ing.ObjectMeta)
			problems[k] = p
		}
	}
}

func (c *Configuration) addProblemsForOrphanOrIgnoredVsrs(problems map[string]ConfigurationProblem) {
	for _, key := range getSortedVirtualServerRouteKeys(c.virtualServerRoutes) {
		vsr := c.virtualServerRoutes[key]

		r, exists := c.hosts[vsr.Spec.Host]
		vsConfig, ok := r.(*VirtualServerConfiguration)

		if !exists || !ok {
			p := ConfigurationProblem{
				Object:  vsr,
				IsError: false,
				Reason:  nl.EventReasonNoVirtualServerFound,
				Message: "VirtualServer is invalid or doesn't exist",
			}
			k := getResourceKeyWithKind(virtualServerRouteKind, &vsr.ObjectMeta)
			problems[k] = p
			continue
		}

		found := false
		for _, v := range vsConfig.VirtualServerRoutes {
			if vsr.Namespace == v.Namespace && vsr.Name == v.Name {
				found = true
				break
			}
		}

		if !found {
			p := ConfigurationProblem{
				Object:  vsr,
				IsError: false,
				Reason:  nl.EventReasonIgnored,
				Message: fmt.Sprintf("VirtualServer %s ignores VirtualServerRoute", getResourceKey(&vsConfig.VirtualServer.ObjectMeta)),
			}
			k := getResourceKeyWithKind(virtualServerRouteKind, &vsr.ObjectMeta)
			problems[k] = p
		}
	}
}

func getResourceKeyWithKind(kind string, objectMeta *metav1.ObjectMeta) string {
	return fmt.Sprintf("%s/%s/%s", kind, objectMeta.Namespace, objectMeta.Name)
}

func createResourceChangesForHosts(removedHosts []string, updatedHosts []string, addedHosts []string, oldHosts map[string]Resource, newHosts map[string]Resource) []ResourceChange {
	var changes []ResourceChange
	var deleteChanges []ResourceChange

	for _, h := range removedHosts {
		change := ResourceChange{
			Op:       Delete,
			Resource: oldHosts[h],
		}
		deleteChanges = append(deleteChanges, change)
	}

	for _, h := range updatedHosts {
		if oldHosts[h].GetKeyWithKind() != newHosts[h].GetKeyWithKind() {
			deleteChange := ResourceChange{
				Op:       Delete,
				Resource: oldHosts[h],
			}
			deleteChanges = append(deleteChanges, deleteChange)
		}

		change := ResourceChange{
			Op:       AddOrUpdate,
			Resource: newHosts[h],
		}
		changes = append(changes, change)
	}

	for _, h := range addedHosts {
		change := ResourceChange{
			Op:       AddOrUpdate,
			Resource: newHosts[h],
		}
		changes = append(changes, change)
	}

	// We need to ensure that delete changes come first.
	// This way an addOrUpdate change, which might include a resource that uses the same host as a resource
	// in a delete change, will be processed only after the config of the delete change is removed.
	// That will prevent any host collisions in the NGINX config in the state between the changes.
	return append(deleteChanges, changes...)
}

func createResourceChangesForListeners(
	removedListeners []listenerHostKey,
	updatedListeners []listenerHostKey,
	addedListeners []listenerHostKey,
	oldListeners map[listenerHostKey]*TransportServerConfiguration,
	newListeners map[listenerHostKey]*TransportServerConfiguration,
) []ResourceChange {
	var changes []ResourceChange
	var deleteChanges []ResourceChange

	for _, l := range removedListeners {
		change := ResourceChange{
			Op:       Delete,
			Resource: oldListeners[l],
		}
		deleteChanges = append(deleteChanges, change)
	}

	for _, l := range updatedListeners {
		if oldListeners[l].GetKeyWithKind() != newListeners[l].GetKeyWithKind() {
			deleteChange := ResourceChange{
				Op:       Delete,
				Resource: oldListeners[l],
			}
			deleteChanges = append(deleteChanges, deleteChange)
		}

		change := ResourceChange{
			Op:       AddOrUpdate,
			Resource: newListeners[l],
		}
		changes = append(changes, change)
	}

	for _, l := range addedListeners {
		change := ResourceChange{
			Op:       AddOrUpdate,
			Resource: newListeners[l],
		}
		changes = append(changes, change)
	}

	// We need to ensure that delete changes come first.
	// This way an addOrUpdate change, which might include a resource that uses the same listener as a resource
	// in a delete change, will be processed only after the config of the delete change is removed.
	// That will prevent any listener collisions in the NGINX config in the state between the changes.
	return append(deleteChanges, changes...)
}

func squashResourceChanges(changes []ResourceChange) []ResourceChange {
	// deletes for the same resource become a single delete
	// updates for the same resource become a single update
	// delete and update for the same resource become a single update

	var deletes []ResourceChange
	var updates []ResourceChange

	changesPerResource := make(map[string][]ResourceChange)

	for _, c := range changes {
		key := c.Resource.GetKeyWithKind()
		changesPerResource[key] = append(changesPerResource[key], c)
	}

	// we range over the changes again to preserver the original order
	for _, c := range changes {
		key := c.Resource.GetKeyWithKind()
		resChanges, exists := changesPerResource[key]

		if !exists {
			continue
		}

		// the last element will be an update (if it exists) or a delete
		squashedChanged := resChanges[len(resChanges)-1]
		if squashedChanged.Op == Delete {
			deletes = append(deletes, squashedChanged)
		} else {
			updates = append(updates, squashedChanged)
		}

		delete(changesPerResource, key)
	}

	// We need to ensure that delete changes come first.
	// This way an addOrUpdate change, which might include a resource that uses the same host/listener as a resource
	// in a delete change, will be processed only after the config of the delete change is removed.
	// That will prevent any host/listener collisions in the NGINX config in the state between the changes.
	return append(deletes, updates...)
}

func (c *Configuration) buildHostsAndResources() (newHosts map[string]Resource, newResources map[string]Resource) {
	newHosts = make(map[string]Resource)
	newResources = make(map[string]Resource)
	var challengesVSR []*conf_v1.VirtualServerRoute

	// Step 1 - Build hosts from Ingress resources

	for _, key := range getSortedIngressKeys(c.ingresses) {
		ing := c.ingresses[key]

		if isMinion(ing) {
			continue
		}

		var resource *IngressConfiguration

		if val := c.isChallengeIngress(ing); val {
			vsr := c.convertIngressToVSR(ing)
			if vsr != nil {
				challengesVSR = append(challengesVSR, vsr)
				continue
			}
		}

		if isMaster(ing) {
			minions, childWarnings := c.buildMinionConfigs(ing.Spec.Rules[0].Host)
			resource = NewMasterIngressConfiguration(ing, minions, childWarnings)
		} else {
			resource = NewRegularIngressConfiguration(ing)
		}

		newResources[resource.GetKeyWithKind()] = resource

		for _, rule := range ing.Spec.Rules {
			holder, exists := newHosts[rule.Host]
			if !exists {
				newHosts[rule.Host] = resource
				continue
			}

			warning := fmt.Sprintf("host %s is taken by another resource", rule.Host)

			if !holder.Wins(resource) {
				holder.AddWarning(warning)
				newHosts[rule.Host] = resource
			} else {
				resource.AddWarning(warning)
			}
		}
	}

	// Step 2 - Build hosts from VirtualServer resources

	for _, key := range getSortedVirtualServerKeys(c.virtualServers) {
		vs := c.virtualServers[key]

		vsrs, warnings := c.buildVirtualServerRoutes(vs)
		for _, vsr := range challengesVSR {
			if vs.Spec.Host == vsr.Spec.Host {
				vsrs = append(vsrs, vsr)
			}
		}
		resource := NewVirtualServerConfiguration(vs, vsrs, warnings)

		c.buildListenersForVSConfiguration(resource)

		newResources[resource.GetKeyWithKind()] = resource

		holder, exists := newHosts[vs.Spec.Host]
		if !exists {
			newHosts[vs.Spec.Host] = resource
			continue
		}

		warning := fmt.Sprintf("host %s is taken by another resource", vs.Spec.Host)

		if !holder.Wins(resource) {
			newHosts[vs.Spec.Host] = resource
			holder.AddWarning(warning)
		} else {
			resource.AddWarning(warning)
		}
	}

	// Step - 3 - Build hosts from TransportServer resources if TLS Passthrough is enabled

	if c.isTLSPassthroughEnabled {
		for _, key := range getSortedTransportServerKeys(c.transportServers) {
			ts := c.transportServers[key]

			if ts.Spec.Listener.Name != conf_v1.TLSPassthroughListenerName && ts.Spec.Listener.Protocol != conf_v1.TLSPassthroughListenerProtocol {
				continue
			}

			resource := NewTransportServerConfiguration(ts)
			newResources[resource.GetKeyWithKind()] = resource

			holder, exists := newHosts[ts.Spec.Host]
			if !exists {
				newHosts[ts.Spec.Host] = resource
				continue
			}

			warning := fmt.Sprintf("host %s is taken by another resource", ts.Spec.Host)

			if !holder.Wins(resource) {
				newHosts[ts.Spec.Host] = resource
				holder.AddWarning(warning)
			} else {
				resource.AddWarning(warning)
			}
		}
	}

	return newHosts, newResources
}

func (c *Configuration) isChallengeIngress(ing *networking.Ingress) bool {
	if !c.isCertManagerEnabled {
		return false
	}
	return ing.Labels["acme.cert-manager.io/http01-solver"] == "true"
}

func (c *Configuration) convertIngressToVSR(ing *networking.Ingress) *conf_v1.VirtualServerRoute {
	rule := ing.Spec.Rules[0]

	if !c.isChallengeIngressOwnerVs(rule.Host) {
		return nil
	}

	vs := &conf_v1.VirtualServerRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ing.Namespace,
			Name:      ing.Name,
		},
		Spec: conf_v1.VirtualServerRouteSpec{
			Host: rule.Host,
			Upstreams: []conf_v1.Upstream{
				{
					Name:    "challenge",
					Service: rule.HTTP.Paths[0].Backend.Service.Name,
					Port:    uint16(rule.HTTP.Paths[0].Backend.Service.Port.Number),
				},
			},
			Subroutes: []conf_v1.Route{
				{
					Path: rule.HTTP.Paths[0].Path,
					Action: &conf_v1.Action{
						Pass: "challenge",
					},
				},
			},
		},
	}

	return vs
}

func (c *Configuration) isChallengeIngressOwnerVs(host string) bool {
	for _, key := range getSortedVirtualServerKeys(c.virtualServers) {
		vs := c.virtualServers[key]
		if host == vs.Spec.Host {
			return true
		}
	}
	return false
}

func (c *Configuration) buildMinionConfigs(masterHost string) ([]*MinionConfiguration, map[string][]string) {
	var minionConfigs []*MinionConfiguration
	childWarnings := make(map[string][]string)
	paths := make(map[string]*MinionConfiguration)

	for _, minionKey := range getSortedIngressKeys(c.ingresses) {
		ingress := c.ingresses[minionKey]

		if !isMinion(ingress) {
			continue
		}

		if masterHost != ingress.Spec.Rules[0].Host {
			continue
		}

		minionConfig := NewMinionConfiguration(ingress)

		for _, p := range ingress.Spec.Rules[0].HTTP.Paths {
			holder, exists := paths[p.Path]
			if !exists {
				paths[p.Path] = minionConfig
				minionConfig.ValidPaths[p.Path] = true
				continue
			}

			warning := fmt.Sprintf("path %s is taken by another resource", p.Path)

			if !chooseObjectMetaWinner(&holder.Ingress.ObjectMeta, &ingress.ObjectMeta) {
				paths[p.Path] = minionConfig
				minionConfig.ValidPaths[p.Path] = true

				holder.ValidPaths[p.Path] = false
				key := getResourceKey(&holder.Ingress.ObjectMeta)
				childWarnings[key] = append(childWarnings[key], warning)
			} else {
				key := getResourceKey(&minionConfig.Ingress.ObjectMeta)
				childWarnings[key] = append(childWarnings[key], warning)
			}
		}

		minionConfigs = append(minionConfigs, minionConfig)
	}

	return minionConfigs, childWarnings
}

func (c *Configuration) buildVirtualServerRoutes(vs *conf_v1.VirtualServer) ([]*conf_v1.VirtualServerRoute, []string) {
	var vsrs []*conf_v1.VirtualServerRoute
	var warnings []string

	for _, r := range vs.Spec.Routes {
		if r.Route == "" {
			continue
		}

		vsrKey := r.Route

		// if route is defined without a namespace, use the namespace of VirtualServer.
		if !strings.Contains(r.Route, "/") {
			vsrKey = fmt.Sprintf("%s/%s", vs.Namespace, r.Route)
		}

		vsr, exists := c.virtualServerRoutes[vsrKey]
		if !exists {
			warning := fmt.Sprintf("VirtualServerRoute %s doesn't exist or invalid", vsrKey)
			warnings = append(warnings, warning)
			continue
		}

		err := c.virtualServerValidator.ValidateVirtualServerRouteForVirtualServer(vsr, vs.Spec.Host, r.Path)
		if err != nil {
			warning := fmt.Sprintf("VirtualServerRoute %s is invalid: %v", vsrKey, err)
			warnings = append(warnings, warning)
			continue
		}

		vsrs = append(vsrs, vsr)
	}

	return vsrs, warnings
}

// GetTransportServerMetrics returns metrics about TransportServers
func (c *Configuration) GetTransportServerMetrics() *TransportServerMetrics {
	var metrics TransportServerMetrics

	if c.isTLSPassthroughEnabled {
		for _, resource := range c.hosts {
			_, ok := resource.(*TransportServerConfiguration)
			if ok {
				metrics.TotalTLSPassthrough++
			}
		}
	}

	for _, tsConfig := range c.listenerHosts {
		if tsConfig.TransportServer.Spec.Listener.Protocol == "TCP" {
			metrics.TotalTCP++
		} else {
			metrics.TotalUDP++
		}
	}

	return &metrics
}

func (c *Configuration) setGlobalConfigListenerMap() {
	c.listenerMap = make(map[string]conf_v1.Listener)

	if c.globalConfiguration != nil {
		for _, listener := range c.globalConfiguration.Spec.Listeners {
			c.listenerMap[listener.Name] = listener
		}
	}
}

func getSortedIngressKeys(m map[string]*networking.Ingress) []string {
	var keys []string

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func getSortedVirtualServerKeys(m map[string]*conf_v1.VirtualServer) []string {
	var keys []string

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func getSortedVirtualServerRouteKeys(m map[string]*conf_v1.VirtualServerRoute) []string {
	var keys []string

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func getSortedProblemKeys(m map[string]ConfigurationProblem) []string {
	var keys []string

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func getSortedResourceKeys(m map[string]Resource) []string {
	var keys []string

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func getSortedTransportServerKeys(m map[string]*conf_v1.TransportServer) []string {
	var keys []string

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func getSortedListenerHostKeys(m map[listenerHostKey]*TransportServerConfiguration) []listenerHostKey {
	var keys []listenerHostKey

	for k := range m {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].String() < keys[j].String()
	})

	return keys
}

func detectChangesInHosts(oldHosts map[string]Resource, newHosts map[string]Resource) (removedHosts []string, updatedHosts []string, addedHosts []string) {
	for _, h := range getSortedResourceKeys(oldHosts) {
		_, exists := newHosts[h]
		if !exists {
			removedHosts = append(removedHosts, h)
		}
	}

	for _, h := range getSortedResourceKeys(newHosts) {
		_, exists := oldHosts[h]
		if !exists {
			addedHosts = append(addedHosts, h)
		}
	}

	for _, h := range getSortedResourceKeys(newHosts) {
		oldR, exists := oldHosts[h]
		if !exists {
			continue
		}
		if !oldR.IsEqual(newHosts[h]) {
			updatedHosts = append(updatedHosts, h)
			continue
		}

		newVsc, newHostOk := newHosts[h].(*VirtualServerConfiguration)
		oldVsc, oldHostOk := oldHosts[h].(*VirtualServerConfiguration)
		if !newHostOk || !oldHostOk {
			continue
		}

		if newVsc.HTTPPort != oldVsc.HTTPPort || newVsc.HTTPSPort != oldVsc.HTTPSPort {
			updatedHosts = append(updatedHosts, h)
		}

		if newVsc.HTTPIPv4 != oldVsc.HTTPIPv4 {
			updatedHosts = append(updatedHosts, h)
		}

		if newVsc.HTTPIPv6 != oldVsc.HTTPIPv6 {
			updatedHosts = append(updatedHosts, h)
		}

	}

	return removedHosts, updatedHosts, addedHosts
}

func detectChangesInListenerHosts(
	oldListenerHosts map[listenerHostKey]*TransportServerConfiguration,
	newListenerHosts map[listenerHostKey]*TransportServerConfiguration,
) (removedListenerHosts []listenerHostKey, updatedListenerHosts []listenerHostKey, addedListenerHosts []listenerHostKey) {
	oldKeys := getSortedListenerHostKeys(oldListenerHosts)
	newKeys := getSortedListenerHostKeys(newListenerHosts)

	oldKeysSet := make(map[listenerHostKey]struct{})
	for _, key := range oldKeys {
		oldKeysSet[key] = struct{}{}
		if _, exists := newListenerHosts[key]; !exists {
			removedListenerHosts = append(removedListenerHosts, key)
		}
	}

	for _, key := range newKeys {
		if _, exists := oldListenerHosts[key]; !exists {
			addedListenerHosts = append(addedListenerHosts, key)
		} else {
			oldConfig := oldListenerHosts[key]
			if !oldConfig.IsEqual(newListenerHosts[key]) {
				updatedListenerHosts = append(updatedListenerHosts, key)
			}
		}
	}

	return removedListenerHosts, updatedListenerHosts, addedListenerHosts
}
