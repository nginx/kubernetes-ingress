// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	k8sv1 "github.com/nginxinc/kubernetes-ingress/v3/pkg/apis/configuration/v1"
	k8sv1alpha1 "github.com/nginxinc/kubernetes-ingress/v3/pkg/apis/configuration/v1alpha1"
	appprotectdosv1beta1 "github.com/nginxinc/kubernetes-ingress/v3/pkg/apis/dos/v1beta1"
	externaldnsv1 "github.com/nginxinc/kubernetes-ingress/v3/pkg/apis/externaldns/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	serializer "k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var scheme = runtime.NewScheme()
var codecs = serializer.NewCodecFactory(scheme)

var localSchemeBuilder = runtime.SchemeBuilder{
	k8sv1.AddToScheme,
	k8sv1alpha1.AddToScheme,
	appprotectdosv1beta1.AddToScheme,
	externaldnsv1.AddToScheme,
}

// AddToScheme adds all types of this clientset into the given scheme. This allows composition
// of clientsets, like in:
//
//	import (
//	  "k8s.io/client-go/kubernetes"
//	  clientsetscheme "k8s.io/client-go/kubernetes/scheme"
//	  aggregatorclientsetscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"
//	)
//
//	kclientset, _ := kubernetes.NewForConfig(c)
//	_ = aggregatorclientsetscheme.AddToScheme(clientsetscheme.Scheme)
//
// After this, RawExtensions in Kubernetes types will serialize kube-aggregator types
// correctly.
var AddToScheme = localSchemeBuilder.AddToScheme

func init() {
	v1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
	utilruntime.Must(AddToScheme(scheme))
}
