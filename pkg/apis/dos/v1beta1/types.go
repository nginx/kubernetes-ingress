package v1beta1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:validation:Optional
// +kubebuilder:resource:shortName=pr

// DosProtectedResource defines a Dos protected resource.
type DosProtectedResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec DosProtectedResourceSpec `json:"spec"`
}

// DosProtectedResourceSpec defines the properties and values a DosProtectedResource can have.
type DosProtectedResourceSpec struct {
	// Enable enables the DOS feature if set to true
	Enable bool `json:"enable"`
	// Name is the name of protected object, max of 63 characters.
	Name         string        `json:"name"`
	ApDosMonitor *ApDosMonitor `json:"apDosMonitor"`
	// DosAccessLogDest is the network address for the access logs
	DosAccessLogDest string `json:"dosAccessLogDest"`
	// ApDosPolicy is the namespace/name of a ApDosPolicy resource
	ApDosPolicy    string          `json:"apDosPolicy"`
	DosSecurityLog *DosSecurityLog `json:"dosSecurityLog"`
	// AllowList is a list of allowed IPs and subnet masks
	AllowList []AllowListEntry `json:"allowList,omitempty"`
}

// AllowListEntry represents an IP address and a subnet mask.
type AllowListEntry struct {
	IPWithMask string `json:"ipWithMask"`
}

// ApDosMonitor is how NGINX App Protect DoS monitors the stress level of the protected object. The monitor requests are sent from localhost (127.0.0.1). Default value: URI - None, protocol - http1, timeout - NGINX App Protect DoS default.
type ApDosMonitor struct {
	// URI is the destination to the desired protected object in the nginx.conf:
	URI string `json:"uri"`
	// +kubebuilder:validation:Enum=http1;http2;grpc;websocket
	// Protocol determines if the server listens on http1 / http2 / grpc / websocket. The default is http1.
	Protocol string `json:"protocol"`
	// Timeout determines how long (in seconds) should NGINX App Protect DoS wait for a response. Default is 10 seconds for http1/http2 and 5 seconds for grpc.
	Timeout uint64 `json:"timeout"`
}

// DosSecurityLog defines the security log of the DosProtectedResource.
type DosSecurityLog struct {
	// Enable enables the security logging feature if set to true
	Enable bool `json:"enable"`
	// ApDosLogConf is the namespace/name of a APDosLogConf resource
	ApDosLogConf string `json:"apDosLogConf"`
	// DosLogDest is the network address of a logging service, can be either IP or DNS name.
	DosLogDest string `json:"dosLogDest"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DosProtectedResourceList is a list of the DosProtectedResource resources.
type DosProtectedResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []DosProtectedResource `json:"items"`
}
