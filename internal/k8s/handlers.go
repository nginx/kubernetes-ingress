package k8s

import (
	"fmt"
	"log/slog"
	"reflect"

	"github.com/jinzhu/copier"

	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/client-go/tools/cache"

	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// createIngressHandlers builds the handler funcs for ingresses
func createIngressHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ingress := obj.(*networking.Ingress)
			nl.Debugf(lbc.Logger, "Adding Ingress: %v", ingress.Name)
			lbc.AddSyncQueue(obj)
		},
		DeleteFunc: func(obj interface{}) {
			ingress, isIng := obj.(*networking.Ingress)
			if !isIng {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					nl.Debugf(lbc.Logger, "Error received unexpected object: %v", obj)
					return
				}
				ingress, ok = deletedState.Obj.(*networking.Ingress)
				if !ok {
					nl.Debugf(lbc.Logger, "Error DeletedFinalStateUnknown contained non-Ingress object: %v", deletedState.Obj)
					return
				}
			}
			nl.Debugf(lbc.Logger, "Removing Ingress: %v", ingress.Name)
			lbc.AddSyncQueue(obj)
		},
		UpdateFunc: func(old, current interface{}) {
			c := current.(*networking.Ingress)
			o := old.(*networking.Ingress)
			if hasChanges(o, c) {
				nl.Debugf(lbc.Logger, "Ingress %v changed, syncing", c.Name)
				lbc.AddSyncQueue(c)
			}
		},
	}
}

// createSecretHandlers builds the handler funcs for secrets
func createSecretHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			secret := obj.(*v1.Secret)
			if !secrets.IsSupportedSecretType(secret.Type) {
				nl.Debugf(lbc.Logger, "Ignoring Secret %v of unsupported type %v", secret.Name, secret.Type)
				return
			}
			nl.Debugf(lbc.Logger, "Adding Secret: %v", secret.Name)
			lbc.AddSyncQueue(obj)
		},
		DeleteFunc: func(obj interface{}) {
			secret, isSecr := obj.(*v1.Secret)
			if !isSecr {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					nl.Debugf(lbc.Logger, "Error received unexpected object: %v", obj)
					return
				}
				secret, ok = deletedState.Obj.(*v1.Secret)
				if !ok {
					nl.Debugf(lbc.Logger, "Error DeletedFinalStateUnknown contained non-Secret object: %v", deletedState.Obj)
					return
				}
			}
			if !secrets.IsSupportedSecretType(secret.Type) {
				nl.Debugf(lbc.Logger, "Ignoring Secret %v of unsupported type %v", secret.Name, secret.Type)
				return
			}

			nl.Debugf(lbc.Logger, "Removing Secret: %v", secret.Name)
			lbc.AddSyncQueue(obj)
		},
		UpdateFunc: func(old, cur interface{}) {
			// A secret cannot change its type. That's why we only need to check the type of the current secret.
			curSecret := cur.(*v1.Secret)
			if !secrets.IsSupportedSecretType(curSecret.Type) {
				nl.Debugf(lbc.Logger, "Ignoring Secret %v of unsupported type %v", curSecret.Name, curSecret.Type)
				return
			}

			if !reflect.DeepEqual(old, cur) {
				nl.Debugf(lbc.Logger, "Secret %v changed, syncing", cur.(*v1.Secret).Name)
				lbc.AddSyncQueue(cur)
			}
		},
	}
}

func createVirtualServerHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			vs := obj.(*conf_v1.VirtualServer)
			nl.Debugf(lbc.Logger, "Adding VirtualServer: %v", vs.Name)
			lbc.AddSyncQueue(vs)
		},
		DeleteFunc: func(obj interface{}) {
			vs, isVs := obj.(*conf_v1.VirtualServer)
			if !isVs {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					nl.Debugf(lbc.Logger, "Error received unexpected object: %v", obj)
					return
				}
				vs, ok = deletedState.Obj.(*conf_v1.VirtualServer)
				if !ok {
					nl.Debugf(lbc.Logger, "Error DeletedFinalStateUnknown contained non-VirtualServer object: %v", deletedState.Obj)
					return
				}
			}
			nl.Debugf(lbc.Logger, "Removing VirtualServer: %v", vs.Name)
			lbc.AddSyncQueue(vs)
		},
		UpdateFunc: func(old, cur interface{}) {
			curVs := cur.(*conf_v1.VirtualServer)
			oldVs := old.(*conf_v1.VirtualServer)

			if lbc.weightChangesDynamicReload {
				var curVsCopy, oldVsCopy conf_v1.VirtualServer
				err := copier.CopyWithOption(&curVsCopy, curVs, copier.Option{DeepCopy: true})
				if err != nil {
					nl.Debugf(lbc.Logger, "Error copying VirtualServer %v: %v for Dynamic Weight Changes", curVs.Name, err)
					return
				}

				err = copier.CopyWithOption(&oldVsCopy, oldVs, copier.Option{DeepCopy: true})
				if err != nil {
					nl.Debugf(lbc.Logger, "Error copying VirtualServer %v: %v for Dynamic Weight Changes", oldVs.Name, err)
					return
				}

				zeroOutVirtualServerSplitWeights(&curVsCopy)
				zeroOutVirtualServerSplitWeights(&oldVsCopy)

				if reflect.DeepEqual(oldVsCopy.Spec, curVsCopy.Spec) {
					lbc.processVSWeightChangesDynamicReload(oldVs, curVs)
					return
				}

			}

			if !reflect.DeepEqual(oldVs.Spec, curVs.Spec) {
				nl.Debugf(lbc.Logger, "VirtualServer %v changed, syncing", curVs.Name)
				lbc.AddSyncQueue(curVs)
			}
		},
	}
}

func createVirtualServerRouteHandlers(lbc *LoadBalancerController) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			vsr := obj.(*conf_v1.VirtualServerRoute)
			nl.Debugf(lbc.Logger, "Adding VirtualServerRoute: %v", vsr.Name)
			lbc.AddSyncQueue(vsr)
		},
		DeleteFunc: func(obj interface{}) {
			vsr, isVsr := obj.(*conf_v1.VirtualServerRoute)
			if !isVsr {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					nl.Debugf(lbc.Logger, "Error received unexpected object: %v", obj)
					return
				}
				vsr, ok = deletedState.Obj.(*conf_v1.VirtualServerRoute)
				if !ok {
					nl.Debugf(lbc.Logger, "Error DeletedFinalStateUnknown contained non-VirtualServerRoute object: %v", deletedState.Obj)
					return
				}
			}
			nl.Debugf(lbc.Logger, "Removing VirtualServerRoute: %v", vsr.Name)
			lbc.AddSyncQueue(vsr)
		},
		UpdateFunc: func(old, cur interface{}) {
			curVsr := cur.(*conf_v1.VirtualServerRoute)
			oldVsr := old.(*conf_v1.VirtualServerRoute)

			if lbc.weightChangesDynamicReload {
				var curVsrCopy, oldVsrCopy conf_v1.VirtualServerRoute
				err := copier.CopyWithOption(&curVsrCopy, curVsr, copier.Option{DeepCopy: true})
				if err != nil {
					nl.Debugf(lbc.Logger, "Error copying VirtualServerRoute %v: %v for Dynamic Weight Changes", curVsr.Name, err)
					return
				}

				err = copier.CopyWithOption(&oldVsrCopy, oldVsr, copier.Option{DeepCopy: true})
				if err != nil {
					nl.Debugf(lbc.Logger, "Error copying VirtualServerRoute %v: %v for Dynamic Weight Changes", oldVsr.Name, err)
					return
				}

				zeroOutVirtualServerRouteSplitWeights(&curVsrCopy)
				zeroOutVirtualServerRouteSplitWeights(&oldVsrCopy)

				if reflect.DeepEqual(oldVsrCopy.Spec, curVsrCopy.Spec) {
					lbc.processVSRWeightChangesDynamicReload(oldVsr, curVsr)
					return
				}

			}

			if !reflect.DeepEqual(oldVsr.Spec, curVsr.Spec) {
				nl.Debugf(lbc.Logger, "VirtualServerRoute %v changed, syncing", curVsr.Name)
				lbc.AddSyncQueue(curVsr)
			}
		},
	}
}

// areResourcesDifferent returns true if the resources are different based on their spec.
func areResourcesDifferent(l *slog.Logger, oldresource, resource *unstructured.Unstructured) (bool, error) {
	oldSpec, found, err := unstructured.NestedMap(oldresource.Object, "spec")
	if !found {
		nl.Debugf(l, "Warning, oldspec has unexpected format")
	}
	if err != nil {
		return false, err
	}
	spec, found, err := unstructured.NestedMap(resource.Object, "spec")
	if err != nil {
		return false, err
	}
	if !found {
		return false, fmt.Errorf("spec has unexpected format")
	}
	eq := reflect.DeepEqual(oldSpec, spec)
	if eq {
		nl.Debugf(l, "New spec of %v same as old spec", oldresource.GetName())
	}
	return !eq, nil
}

func zeroOutVirtualServerSplitWeights(vs *conf_v1.VirtualServer) {
	for _, route := range vs.Spec.Routes {
		for _, match := range route.Matches {
			if len(match.Splits) == 2 {
				match.Splits[0].Weight = 0
				match.Splits[1].Weight = 0
			}
		}

		if len(route.Splits) == 2 {
			route.Splits[0].Weight = 0
			route.Splits[1].Weight = 0
		}
	}
}

func zeroOutVirtualServerRouteSplitWeights(vs *conf_v1.VirtualServerRoute) {
	for _, route := range vs.Spec.Subroutes {
		for _, match := range route.Matches {
			if len(match.Splits) == 2 {
				match.Splits[0].Weight = 0
				match.Splits[1].Weight = 0
			}
		}

		if len(route.Splits) == 2 {
			route.Splits[0].Weight = 0
			route.Splits[1].Weight = 0
		}
	}
}
