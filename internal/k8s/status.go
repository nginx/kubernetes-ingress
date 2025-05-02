package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"strconv"
	"strings"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	k8s_nginx "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned"
	api_v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	typednetworking "k8s.io/client-go/kubernetes/typed/networking/v1"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// statusUpdater reports Ingress, VirtualServer and VirtualServerRoute status information via the kubernetes
// API. For external information, it primarily reports the IP or host of the LoadBalancer Service exposing the
// Ingress Controller, or an external IP specified in the ConfigMap.
type statusUpdater struct {
	client                   kubernetes.Interface
	namespace                string
	externalServiceName      string
	externalStatusAddress    string
	externalServiceAddresses []string
	externalServicePorts     string
	bigIPAddress             string
	bigIPPorts               string
	externalEndpoints        []conf_v1.ExternalEndpoint
	status                   []networking.IngressLoadBalancerIngress
	statusInitialized        bool
	keyFunc                  func(obj interface{}) (string, error)
	namespacedInformers      map[string]*namespacedInformer
	confClient               k8s_nginx.Interface
	hasCorrectIngressClass   func(interface{}) bool
	logger                   *slog.Logger
}

func (su *statusUpdater) UpdateExternalEndpointsForResources(resource []Resource) error {
	failed := false

	for _, r := range resource {
		err := su.UpdateExternalEndpointsForResource(r)
		if err != nil {
			failed = true
		}
	}

	if failed {
		return fmt.Errorf("not all Resources updated")
	}

	return nil
}

func (su *statusUpdater) UpdateExternalEndpointsForResource(r Resource) error {
	switch impl := r.(type) {
	case *IngressConfiguration:
		var ings []networking.Ingress
		ings = append(ings, *impl.Ingress)

		for _, fm := range impl.Minions {
			ings = append(ings, *fm.Ingress)
		}

		return su.BulkUpdateIngressStatus(ings)
	case *VirtualServerConfiguration:
		failed := false

		err := su.updateVirtualServerExternalEndpoints(impl.VirtualServer)
		if err != nil {
			failed = true
		}

		for _, vsr := range impl.VirtualServerRoutes {
			err := su.updateVirtualServerRouteExternalEndpoints(vsr)
			if err != nil {
				failed = true
			}
		}

		if failed {
			return fmt.Errorf("not all Resources updated")
		}
	}

	return nil
}

// ClearIngressStatus clears the Ingress status.
func (su *statusUpdater) ClearIngressStatus(ing networking.Ingress) error {
	return su.updateIngressWithStatus(ing, []networking.IngressLoadBalancerIngress{})
}

// UpdateIngressStatus updates the status on the selected Ingress.
func (su *statusUpdater) UpdateIngressStatus(ing networking.Ingress) error {
	if !su.statusInitialized {
		return nil
	}
	return su.updateIngressWithStatus(ing, su.status)
}

func (su *statusUpdater) getNamespacedInformer(ns string) *namespacedInformer {
	var nsi *namespacedInformer
	var isGlobalNs bool
	var exists bool

	nsi, isGlobalNs = su.namespacedInformers[""]

	if !isGlobalNs {
		// get the correct namespaced informers
		nsi, exists = su.namespacedInformers[ns]
		if !exists {
			// we are not watching this namespace
			return nil
		}
	}
	return nsi
}

// updateIngressWithStatus sets the provided status on the selected Ingress.
func (su *statusUpdater) updateIngressWithStatus(ing networking.Ingress, status []networking.IngressLoadBalancerIngress) error {
	// Get an up-to-date Ingress from the Store
	key, err := su.keyFunc(&ing)
	if err != nil {
		nl.Infof(su.logger, "error getting key for ing: %v", err)
		return err
	}

	ns, _, _ := cache.SplitMetaNamespaceKey(key)
	var ingCopy *networking.Ingress
	var exists bool
	ingCopy, exists, err = su.getNamespacedInformer(ns).ingressLister.GetByKeySafe(key)
	if err != nil {
		nl.Infof(su.logger, "error getting ing from Store by key: %v", err)
		return err
	}
	if !exists {
		nl.Infof(su.logger, "ing doesn't exist in Store")
		return nil
	}

	// No need to update status
	if reflect.DeepEqual(ingCopy.Status.LoadBalancer.Ingress, status) {
		return nil
	}

	ingCopy.Status.LoadBalancer.Ingress = status
	clientIngress := su.client.NetworkingV1().Ingresses(ingCopy.Namespace)
	_, err = clientIngress.UpdateStatus(context.TODO(), ingCopy, metav1.UpdateOptions{})
	if err != nil {
		nl.Infof(su.logger, "error setting ingress status: %v", err)
		err = su.retryStatusUpdate(clientIngress, ingCopy)
		if err != nil {
			nl.Infof(su.logger, "error retrying status update: %v", err)
			return err
		}
	}
	nl.Infof(su.logger, "updated status for ing: %v %v", ing.Namespace, ing.Name)
	return nil
}

// BulkUpdateIngressStatus sets the status field on the selected Ingresses, specifically
// the External IP field.
func (su *statusUpdater) BulkUpdateIngressStatus(ings []networking.Ingress) error {
	if len(ings) < 1 {
		nl.Info(su.logger, "no ingresses to update")
		return nil
	}
	failed := false
	for _, ing := range ings {
		err := su.updateIngressWithStatus(ing, su.status)
		if err != nil {
			failed = true
		}
	}
	if failed {
		return fmt.Errorf("not all Ingresses updated")
	}
	return nil
}

// retryStatusUpdate fetches a fresh copy of the Ingress from the k8s API, checks if it still needs to be
// updated, and then attempts to update. We often need to fetch fresh copies due to the
// k8s API using ResourceVersion to stop updates on stale items.
func (su *statusUpdater) retryStatusUpdate(clientIngress typednetworking.IngressInterface, ingCopy *networking.Ingress) error {
	apiIng, err := clientIngress.Get(context.TODO(), ingCopy.Name, metav1.GetOptions{})
	if err != nil {
		nl.Infof(su.logger, "error getting ingress resource: %v", err)
		return err
	}
	if !reflect.DeepEqual(ingCopy.Status.LoadBalancer, apiIng.Status.LoadBalancer) {
		nl.Infof(su.logger, "retrying update status for ingress: %v, %v", ingCopy.Namespace, ingCopy.Name)
		apiIng.Status.LoadBalancer = ingCopy.Status.LoadBalancer
		_, err := clientIngress.UpdateStatus(context.TODO(), apiIng, metav1.UpdateOptions{})
		if err != nil {
			nl.Infof(su.logger, "update retry failed: %v", err)
		}
		return err
	}
	return nil
}

// saveStatus saves the string array of IPs or addresses that we will set as status
// on all the Ingresses that we manage.
func (su *statusUpdater) saveStatus(ips []string) {
	statusIngs := []networking.IngressLoadBalancerIngress{}
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			statusIngs = append(statusIngs, networking.IngressLoadBalancerIngress{Hostname: ip})
		} else {
			statusIngs = append(statusIngs, networking.IngressLoadBalancerIngress{IP: ip})
		}
	}
	su.status = statusIngs
	su.statusInitialized = true
}

var (
	intPorts    = [2]int32{80, 443}
	stringPorts = [2]string{"http", "https"}
)

func isRequiredPort(port intstr.IntOrString) bool {
	if port.Type == intstr.Int {
		for _, p := range intPorts {
			if p == port.IntVal {
				return true
			}
		}
	} else if port.Type == intstr.String {
		for _, p := range stringPorts {
			if p == port.StrVal {
				return true
			}
		}
	}

	return false
}

func getExternalServicePorts(svc *api_v1.Service) string {
	var ports []string
	if svc == nil {
		return ""
	}

	for _, port := range svc.Spec.Ports {
		if isRequiredPort(port.TargetPort) {
			ports = append(ports, strconv.Itoa(int(port.Port)))
		}
	}

	return fmt.Sprintf("[%v]", strings.Join(ports, ","))
}

func getExternalServiceAddress(svc *api_v1.Service) []string {
	addresses := []string{}
	if svc == nil {
		return addresses
	}

	if svc.Spec.Type == api_v1.ServiceTypeExternalName {
		addresses = append(addresses, svc.Spec.ExternalName)
		return addresses
	}

	for _, ip := range svc.Status.LoadBalancer.Ingress {
		if ip.IP == "" {
			addresses = append(addresses, ip.Hostname)
		} else {
			addresses = append(addresses, ip.IP)
		}
	}
	addresses = append(addresses, svc.Spec.ExternalIPs...)
	return addresses
}

// SaveStatusFromExternalStatus saves the status from a string.
// For use with the external-status-address ConfigMap setting.
// This method does not update ingress status - statusUpdater.UpdateIngressStatus must be called separately.
func (su *statusUpdater) SaveStatusFromExternalStatus(externalStatusAddress string) {
	su.externalStatusAddress = externalStatusAddress
	if externalStatusAddress == "" {
		// if external-status-address was removed from configMap

		// fall back on external service if it exists
		if len(su.externalServiceAddresses) > 0 {
			su.saveStatus(su.externalServiceAddresses)
			su.externalEndpoints = su.generateExternalEndpointsFromStatus(su.status)
			return
		}

		// fall back on IngressLink if it exists
		if su.bigIPAddress != "" {
			su.saveStatus([]string{su.bigIPAddress})
			su.externalEndpoints = su.generateExternalEndpointsFromStatus(su.status)
			return
		}
	}
	ips := []string{}
	ips = append(ips, su.externalStatusAddress)
	su.saveStatus(ips)
	su.externalEndpoints = su.generateExternalEndpointsFromStatus(su.status)
}

// ClearStatusFromExternalService clears the saved status from the External Service
func (su *statusUpdater) ClearStatusFromExternalService() {
	su.SaveStatusFromExternalService(nil)
}

// SaveStatusFromExternalService saves the external IP or address from the service.
// This method does not update ingress status - UpdateIngressStatus must be called separately.
func (su *statusUpdater) SaveStatusFromExternalService(svc *api_v1.Service) {
	ips := getExternalServiceAddress(svc)
	su.externalServiceAddresses = ips
	ports := getExternalServicePorts(svc)
	su.externalServicePorts = ports
	if su.externalStatusAddress != "" {
		nl.Info(su.logger, "skipping external service address/ports - external-status-address is set and takes precedence")
		return
	}
	su.saveStatus(ips)
	su.externalEndpoints = su.generateExternalEndpointsFromStatus(su.status)
}

func (su *statusUpdater) SaveStatusFromIngressLink(ip string) {
	su.bigIPAddress = ip
	su.bigIPPorts = "[80,443]"

	if su.externalStatusAddress != "" {
		nl.Info(su.logger, "skipping IngressLink address - external-status-address is set and takes precedence")
		return
	}

	ips := []string{su.bigIPAddress}
	su.saveStatus(ips)
	su.externalEndpoints = su.generateExternalEndpointsFromStatus(su.status)
}

func (su *statusUpdater) ClearStatusFromIngressLink() {
	su.bigIPAddress = ""
	su.bigIPPorts = ""

	if su.externalStatusAddress != "" {
		nl.Info(su.logger, "skipping IngressLink address - external-status-address is set and takes precedence")
		return
	}

	ips := []string{}
	su.saveStatus(ips)
	su.externalEndpoints = su.generateExternalEndpointsFromStatus(su.status)
}

func (su *statusUpdater) retryUpdateTransportServerStatus(tsCopy *conf_v1.TransportServer) error {
	ts, err := su.confClient.K8sV1().TransportServers(tsCopy.Namespace).Get(context.TODO(), tsCopy.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	ts.Status = tsCopy.Status
	_, err = su.confClient.K8sV1().TransportServers(ts.Namespace).UpdateStatus(context.TODO(), ts, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (su *statusUpdater) retryUpdateVirtualServerStatus(vsCopy *conf_v1.VirtualServer) error {
	vs, err := su.confClient.K8sV1().VirtualServers(vsCopy.Namespace).Get(context.TODO(), vsCopy.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	vs.Status = vsCopy.Status
	_, err = su.confClient.K8sV1().VirtualServers(vs.Namespace).UpdateStatus(context.TODO(), vs, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (su *statusUpdater) retryUpdateVirtualServerRouteStatus(vsrCopy *conf_v1.VirtualServerRoute) error {
	vsr, err := su.confClient.K8sV1().VirtualServerRoutes(vsrCopy.Namespace).Get(context.TODO(), vsrCopy.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	vsr.Status = vsrCopy.Status
	_, err = su.confClient.K8sV1().VirtualServerRoutes(vsr.Namespace).UpdateStatus(context.TODO(), vsr, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func hasVsStatusChanged(vs *conf_v1.VirtualServer, state string, reason string, message string) bool {
	if vs.Status.State != state {
		return true
	}

	if vs.Status.Reason != reason {
		return true
	}

	if vs.Status.Message != message {
		return true
	}

	return false
}

// UpdateTransportServerStatus updates the status of a TransportServer.
func (su *statusUpdater) UpdateTransportServerStatus(ts *conf_v1.TransportServer, state string, reason string, message string) error {
	var tsLatest interface{}
	var exists bool
	var err error

	tsLatest, exists, err = su.getNamespacedInformer(ts.Namespace).transportServerLister.Get(ts)
	if err != nil {
		nl.Infof(su.logger, "error getting TransportServer from Store: %v", err)
		return err
	}
	if !exists {
		nl.Infof(su.logger, "TransportServer doesn't exist in Store")
		return nil
	}

	if !hasTsStatusChanged(tsLatest.(*conf_v1.TransportServer), state, reason, message) {
		return nil
	}

	tsCopy := tsLatest.(*conf_v1.TransportServer).DeepCopy()
	tsCopy.Status.State = state
	tsCopy.Status.Reason = reason
	tsCopy.Status.Message = message

	_, err = su.confClient.K8sV1().TransportServers(tsCopy.Namespace).UpdateStatus(context.TODO(), tsCopy, metav1.UpdateOptions{})
	if err != nil {
		nl.Infof(su.logger, "error setting TransportServer %v/%v status, retrying: %v", tsCopy.Namespace, tsCopy.Name, err)
		return su.retryUpdateTransportServerStatus(tsCopy)
	}
	return err
}

func hasTsStatusChanged(ts *conf_v1.TransportServer, state string, reason string, message string) bool {
	if ts.Status.State != state {
		return true
	}
	if ts.Status.Reason != reason {
		return true
	}
	if ts.Status.Message != message {
		return true
	}
	return false
}

// UpdateVirtualServerStatus updates the status of a VirtualServer.
func (su *statusUpdater) UpdateVirtualServerStatus(vs *conf_v1.VirtualServer, state string, reason string, message string) error {
	// Get an up-to-date VirtualServer from the Store
	var vsLatest interface{}
	var exists bool
	var err error

	vsLatest, exists, err = su.getNamespacedInformer(vs.Namespace).virtualServerLister.Get(vs)
	if err != nil {
		nl.Infof(su.logger, "error getting VirtualServer from Store: %v", err)
		return err
	}
	if !exists {
		nl.Infof(su.logger, "VirtualServer doesn't exist in Store")
		return nil
	}

	vsCopy := vsLatest.(*conf_v1.VirtualServer).DeepCopy()

	if !hasVsStatusChanged(vsCopy, state, reason, message) {
		return nil
	}

	vsCopy.Status.State = state
	vsCopy.Status.Reason = reason
	vsCopy.Status.Message = message
	vsCopy.Status.ExternalEndpoints = su.externalEndpoints

	_, err = su.confClient.K8sV1().VirtualServers(vsCopy.Namespace).UpdateStatus(context.TODO(), vsCopy, metav1.UpdateOptions{})
	if err != nil {
		nl.Infof(su.logger, "error setting VirtualServer %v/%v status, retrying: %v", vsCopy.Namespace, vsCopy.Name, err)
		return su.retryUpdateVirtualServerStatus(vsCopy)
	}
	return err
}

func hasVsrStatusChanged(vsr *conf_v1.VirtualServerRoute, state string, reason string, message string, referencedByString string) bool {
	if vsr.Status.State != state {
		return true
	}

	if vsr.Status.Reason != reason {
		return true
	}

	if vsr.Status.Message != message {
		return true
	}

	if referencedByString != "" && vsr.Status.ReferencedBy != referencedByString {
		return true
	}

	return false
}

// UpdateVirtualServerRouteStatusWithReferencedBy updates the status of a VirtualServerRoute, including the referencedBy field.
func (su *statusUpdater) UpdateVirtualServerRouteStatusWithReferencedBy(vsr *conf_v1.VirtualServerRoute, state string, reason string, message string, referencedBy []*conf_v1.VirtualServer) error {
	var referencedByString string
	if len(referencedBy) != 0 {
		vs := referencedBy[0]
		referencedByString = fmt.Sprintf("%v/%v", vs.Namespace, vs.Name)
	}

	// Get an up-to-date VirtualServerRoute from the Store
	var vsrLatest interface{}
	var exists bool
	var err error

	vsrLatest, exists, err = su.getNamespacedInformer(vsr.Namespace).virtualServerRouteLister.Get(vsr)
	if err != nil {
		nl.Infof(su.logger, "error getting VirtualServerRoute from Store: %v", err)
		return err
	}
	if !exists {
		nl.Infof(su.logger, "VirtualServerRoute doesn't exist in Store")
		return nil
	}

	vsrCopy := vsrLatest.(*conf_v1.VirtualServerRoute).DeepCopy()

	if !hasVsrStatusChanged(vsrCopy, state, reason, message, referencedByString) {
		return nil
	}

	vsrCopy.Status.State = state
	vsrCopy.Status.Reason = reason
	vsrCopy.Status.Message = message
	vsrCopy.Status.ReferencedBy = referencedByString
	vsrCopy.Status.ExternalEndpoints = su.externalEndpoints

	_, err = su.confClient.K8sV1().VirtualServerRoutes(vsrCopy.Namespace).UpdateStatus(context.TODO(), vsrCopy, metav1.UpdateOptions{})
	if err != nil {
		nl.Infof(su.logger, "error setting VirtualServerRoute %v/%v status, retrying: %v", vsrCopy.Namespace, vsrCopy.Name, err)
		return su.retryUpdateVirtualServerRouteStatus(vsrCopy)
	}
	return err
}

// UpdateVirtualServerRouteStatus updates the status of a VirtualServerRoute.
// This method does not clear or update the referencedBy field of the status.
// If you need to update the referencedBy field, use UpdateVirtualServerRouteStatusWithReferencedBy instead.
func (su *statusUpdater) UpdateVirtualServerRouteStatus(vsr *conf_v1.VirtualServerRoute, state string, reason string, message string) error {
	// Get an up-to-date VirtualServerRoute from the Store
	var vsrLatest interface{}
	var exists bool
	var err error

	vsrLatest, exists, err = su.getNamespacedInformer(vsr.Namespace).virtualServerRouteLister.Get(vsr)
	if err != nil {
		nl.Infof(su.logger, "error getting VirtualServerRoute from Store: %v", err)
		return err
	}
	if !exists {
		nl.Infof(su.logger, "VirtualServerRoute doesn't exist in Store")
		return nil
	}

	vsrCopy := vsrLatest.(*conf_v1.VirtualServerRoute).DeepCopy()

	if !hasVsrStatusChanged(vsrCopy, state, reason, message, "") {
		return nil
	}

	vsrCopy.Status.State = state
	vsrCopy.Status.Reason = reason
	vsrCopy.Status.Message = message
	vsrCopy.Status.ExternalEndpoints = su.externalEndpoints

	_, err = su.confClient.K8sV1().VirtualServerRoutes(vsrCopy.Namespace).UpdateStatus(context.TODO(), vsrCopy, metav1.UpdateOptions{})
	if err != nil {
		nl.Infof(su.logger, "error setting VirtualServerRoute %v/%v status, retrying: %v", vsrCopy.Namespace, vsrCopy.Name, err)
		return su.retryUpdateVirtualServerRouteStatus(vsrCopy)
	}
	return err
}

func (su *statusUpdater) updateVirtualServerExternalEndpoints(vs *conf_v1.VirtualServer) error {
	// Get a pristine VirtualServer from the Store
	var vsLatest interface{}
	var exists bool
	var err error

	vsLatest, exists, err = su.getNamespacedInformer(vs.Namespace).virtualServerLister.Get(vs)
	if err != nil {
		nl.Infof(su.logger, "error getting VirtualServer from Store: %v", err)
		return err
	}
	if !exists {
		nl.Infof(su.logger, "VirtualServer doesn't exist in Store")
		return nil
	}

	vsCopy := vsLatest.(*conf_v1.VirtualServer).DeepCopy()
	vsCopy.Status.ExternalEndpoints = su.externalEndpoints

	_, err = su.confClient.K8sV1().VirtualServers(vsCopy.Namespace).UpdateStatus(context.TODO(), vsCopy, metav1.UpdateOptions{})
	if err != nil {
		nl.Infof(su.logger, "error setting VirtualServer %v/%v status, retrying: %v", vsCopy.Namespace, vsCopy.Name, err)
		return su.retryUpdateVirtualServerStatus(vsCopy)
	}
	return err
}

func (su *statusUpdater) updateVirtualServerRouteExternalEndpoints(vsr *conf_v1.VirtualServerRoute) error {
	// Get an up-to-date VirtualServerRoute from the Store
	var vsrLatest interface{}
	var exists bool
	var err error

	vsrLatest, exists, err = su.getNamespacedInformer(vsr.Namespace).virtualServerRouteLister.Get(vsr)
	if err != nil {
		nl.Infof(su.logger, "error getting VirtualServerRoute from Store: %v", err)
		return err
	}
	if !exists {
		nl.Infof(su.logger, "VirtualServerRoute doesn't exist in Store")
		return nil
	}

	vsrCopy := vsrLatest.(*conf_v1.VirtualServerRoute).DeepCopy()
	vsrCopy.Status.ExternalEndpoints = su.externalEndpoints

	_, err = su.confClient.K8sV1().VirtualServerRoutes(vsrCopy.Namespace).UpdateStatus(context.TODO(), vsrCopy, metav1.UpdateOptions{})
	if err != nil {
		nl.Infof(su.logger, "error setting VirtualServerRoute %v/%v status, retrying: %v", vsrCopy.Namespace, vsrCopy.Name, err)
		return su.retryUpdateVirtualServerRouteStatus(vsrCopy)
	}
	return err
}

func (su *statusUpdater) generateExternalEndpointsFromStatus(status []networking.IngressLoadBalancerIngress) []conf_v1.ExternalEndpoint {
	var externalEndpoints []conf_v1.ExternalEndpoint
	for _, lb := range status {
		ports := su.externalServicePorts
		if su.bigIPPorts != "" {
			ports = su.bigIPPorts
		}

		endpoint := conf_v1.ExternalEndpoint{IP: lb.IP, Hostname: lb.Hostname, Ports: ports}
		externalEndpoints = append(externalEndpoints, endpoint)
	}

	return externalEndpoints
}

func hasPolicyStatusChanged(pol *conf_v1.Policy, state string, reason string, message string) bool {
	return pol.Status.State != state || pol.Status.Reason != reason || pol.Status.Message != message
}

// UpdatePolicyStatus updates the status of a Policy.
func (su *statusUpdater) UpdatePolicyStatus(pol *conf_v1.Policy, state string, reason string, message string) error {
	// Get an up-to-date Policy from the Store
	var polLatest interface{}
	var exists bool
	var err error

	polLatest, exists, err = su.getNamespacedInformer(pol.Namespace).policyLister.Get(pol)
	if err != nil {
		nl.Infof(su.logger, "error getting policy from Store: %v", err)
		return err
	}
	if !exists {
		nl.Infof(su.logger, "Policy doesn't exist in Store")
		return nil
	}

	if !su.hasCorrectIngressClass(polLatest) {
		nl.Infof(su.logger, "ignoring policy with incorrect ingress class")
		return nil
	}

	polCopy := polLatest.(*conf_v1.Policy)

	if !hasPolicyStatusChanged(polCopy, state, reason, message) {
		return nil
	}

	polCopy.Status.State = state
	polCopy.Status.Reason = reason
	polCopy.Status.Message = message

	_, err = su.confClient.K8sV1().Policies(polCopy.Namespace).UpdateStatus(context.TODO(), polCopy, metav1.UpdateOptions{})
	if err != nil {
		nl.Infof(su.logger, "error setting Policy %v/%v status, retrying: %v", polCopy.Namespace, polCopy.Name, err)
		return su.retryUpdatePolicyStatus(polCopy)
	}

	return nil
}

func (su *statusUpdater) retryUpdatePolicyStatus(polCopy *conf_v1.Policy) error {
	pol, err := su.confClient.K8sV1().Policies(polCopy.Namespace).Get(context.TODO(), polCopy.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	pol.Status = polCopy.Status
	_, err = su.confClient.K8sV1().Policies(pol.Namespace).UpdateStatus(context.TODO(), pol, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return nil
}
