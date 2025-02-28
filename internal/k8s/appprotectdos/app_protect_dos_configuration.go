package appprotectdos

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/internal/errors"
	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/k8s/appprotectcommon"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/pkg/apis/dos/v1beta1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/dos/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// DosPolicyGVR is the group version resource of the appprotectdos policy
	DosPolicyGVR = schema.GroupVersionResource{
		Group:    "appprotectdos.f5.com",
		Version:  "v1beta1",
		Resource: "apdospolicies",
	}

	// DosPolicyGVK is the group version kind of the appprotectdos policy
	DosPolicyGVK = schema.GroupVersionKind{
		Group:   "appprotectdos.f5.com",
		Version: "v1beta1",
		Kind:    "APDosPolicy",
	}

	// DosLogConfGVR is the group version resource of the appprotectdos policy
	DosLogConfGVR = schema.GroupVersionResource{
		Group:    "appprotectdos.f5.com",
		Version:  "v1beta1",
		Resource: "apdoslogconfs",
	}
	// DosLogConfGVK is the group version kind of the appprotectdos policy
	DosLogConfGVK = schema.GroupVersionKind{
		Group:   "appprotectdos.f5.com",
		Version: "v1beta1",
		Kind:    "APDosLogConf",
	}
)

// Operation defines an operation to perform for an App Protect Dos resource.
type Operation int

const (
	// Delete the config of the resource
	Delete Operation = iota
	// AddOrUpdate the config of the resource
	AddOrUpdate
)

// Change represents a change in an App Protect Dos resource
type Change struct {
	// Op is an operation that needs be performed on the resource.
	Op Operation
	// Resource is the target resource.
	Resource interface{}
}

// Problem represents a problem with an App Protect Dos resource
type Problem struct {
	// Object is a configuration object.
	Object runtime.Object
	// Reason tells the reason. It matches the reason in the events of our configuration objects.
	Reason string
	// Message gives the details about the problem. It matches the message in the events of our configuration objects.
	Message string
}

// Configuration holds representations of App Protect Dos cluster resources
type Configuration struct {
	dosPolicies          map[string]*DosPolicyEx
	dosLogConfs          map[string]*DosLogConfEx
	dosProtectedResource map[string]*DosProtectedResourceEx
	isDosEnabled         bool
}

// NewConfiguration creates a new App Protect Dos Configuration
func NewConfiguration(isDosEnabled bool) *Configuration {
	return &Configuration{
		dosPolicies:          make(map[string]*DosPolicyEx),
		dosLogConfs:          make(map[string]*DosLogConfEx),
		dosProtectedResource: make(map[string]*DosProtectedResourceEx),
		isDosEnabled:         isDosEnabled,
	}
}

// DosProtectedResourceEx represents an DosProtectedResource cluster resource
type DosProtectedResourceEx struct {
	Obj      *v1beta1.DosProtectedResource
	IsValid  bool
	ErrorMsg string
}

// DosPolicyEx represents an DosPolicy cluster resource
type DosPolicyEx struct {
	Obj      *unstructured.Unstructured
	IsValid  bool
	ErrorMsg string
}

// DosLogConfEx represents an DosLogConf cluster resource
type DosLogConfEx struct {
	Obj      *unstructured.Unstructured
	IsValid  bool
	ErrorMsg string
}

// AddOrUpdatePolicy adds or updates an App Protect Dos Policy to App Protect Dos Configuration
func (ci *Configuration) AddOrUpdatePolicy(policyObj *unstructured.Unstructured) (changes []Change, problems []Problem) {
	resNsName := appprotectcommon.GetNsName(policyObj)
	policy, err := createAppProtectDosPolicyEx(policyObj)
	ci.dosPolicies[resNsName] = policy
	op := AddOrUpdate
	if err != nil {
		op = Delete
		problems = append(problems, Problem{Object: policyObj, Reason: nl.EventReasonRejected, Message: err.Error()})
	}

	changes = append(changes, Change{Op: op, Resource: policy})

	protectedResources := ci.GetDosProtectedThatReferencedDosPolicy(resNsName)
	for _, p := range protectedResources {
		proChanges, proProblems := ci.AddOrUpdateDosProtectedResource(p)
		changes = append(changes, proChanges...)
		problems = append(problems, proProblems...)
	}

	return changes, problems
}

// AddOrUpdateLogConf adds or updates App Protect Dos Log Configuration to App Protect Dos Configuration
func (ci *Configuration) AddOrUpdateLogConf(logConfObj *unstructured.Unstructured) (changes []Change, problems []Problem) {
	resNsName := appprotectcommon.GetNsName(logConfObj)
	logConf, err := createAppProtectDosLogConfEx(logConfObj)
	ci.dosLogConfs[resNsName] = logConf
	op := AddOrUpdate
	if err != nil {
		op = Delete
		problems = append(problems, Problem{Object: logConfObj, Reason: nl.EventReasonRejected, Message: err.Error()})
	}

	changes = append(changes, Change{Op: op, Resource: logConf})

	protectedResources := ci.GetDosProtectedThatReferencedDosLogConf(resNsName)
	for _, p := range protectedResources {
		proChanges, proProblems := ci.AddOrUpdateDosProtectedResource(p)
		changes = append(changes, proChanges...)
		problems = append(problems, proProblems...)
	}

	return changes, problems
}

// AddOrUpdateDosProtectedResource adds or updates App Protect Dos ProtectedResource Configuration
func (ci *Configuration) AddOrUpdateDosProtectedResource(protectedConf *v1beta1.DosProtectedResource) ([]Change, []Problem) {
	resNsName := protectedConf.Namespace + "/" + protectedConf.Name
	protectedEx, err := createDosProtectedResourceEx(protectedConf)
	ci.dosProtectedResource[resNsName] = protectedEx
	if err != nil {
		return []Change{{Op: Delete, Resource: protectedEx}},
			[]Problem{{Object: protectedConf, Reason: nl.EventReasonRejected, Message: err.Error()}}
	}
	if protectedEx.Obj.Spec.ApDosPolicy != "" {
		policyReference := protectedEx.Obj.Spec.ApDosPolicy
		// if the policy reference does not have a namespace, use the dos protected' namespace
		if !strings.Contains(policyReference, "/") {
			policyReference = protectedEx.Obj.Namespace + "/" + policyReference
		}
		_, err := ci.getPolicy(policyReference)
		if err != nil {
			return []Change{{Op: Delete, Resource: protectedEx}},
				[]Problem{{Object: protectedConf, Reason: nl.EventReasonRejected, Message: fmt.Sprintf("dos protected refers (%s) to an invalid DosPolicy: %s", policyReference, err.Error())}}
		}
	}
	if protectedEx.Obj.Spec.DosSecurityLog != nil && protectedEx.Obj.Spec.DosSecurityLog.ApDosLogConf != "" {
		logConfReference := protectedEx.Obj.Spec.DosSecurityLog.ApDosLogConf
		// if the log conf reference does not have a namespace, use the dos protected' namespace
		if !strings.Contains(logConfReference, "/") {
			logConfReference = protectedEx.Obj.Namespace + "/" + logConfReference
		}
		_, err := ci.getLogConf(logConfReference)
		if err != nil {
			return []Change{{Op: Delete, Resource: protectedEx}},
				[]Problem{{Object: protectedConf, Reason: nl.EventReasonRejected, Message: fmt.Sprintf("dos protected refers (%s) to an invalid DosLogConf: %s", logConfReference, err.Error())}}
		}
	}
	return []Change{{Op: AddOrUpdate, Resource: protectedEx}}, nil
}

func (ci *Configuration) getPolicy(key string) (*unstructured.Unstructured, error) {
	obj, ok := ci.dosPolicies[key]
	if !ok {
		return nil, fmt.Errorf("DosPolicy %s not found", key)
	}
	if !obj.IsValid {
		return nil, errors.New(obj.ErrorMsg)
	}
	return obj.Obj, nil
}

func (ci *Configuration) getLogConf(key string) (*unstructured.Unstructured, error) {
	obj, ok := ci.dosLogConfs[key]
	if !ok {
		return nil, fmt.Errorf("DosLogConf %s not found", key)
	}
	if !obj.IsValid {
		return nil, errors.New(obj.ErrorMsg)
	}
	return obj.Obj, nil
}

func (ci *Configuration) getDosProtected(key string) (*v1beta1.DosProtectedResource, error) {
	if obj, ok := ci.dosProtectedResource[key]; ok {
		if obj.IsValid {
			return obj.Obj, nil
		}
		return nil, errors.New(obj.ErrorMsg)
	}
	return nil, fmt.Errorf("DosProtectedResource %s not found", key)
}

// GetValidDosEx returns a valid DosProtectedResource - extended with referenced policies and logs
func (ci *Configuration) GetValidDosEx(parentNamespace string, nsName string) (*configs.DosEx, error) {
	key := getNsName(parentNamespace, nsName)
	if !ci.isDosEnabled {
		return nil, fmt.Errorf("DosProtectedResource is referenced but Dos feature is not enabled. resource: %v", key)
	}
	dosEx := &configs.DosEx{}
	protectedEx, ok := ci.dosProtectedResource[key]
	if !ok {
		return nil, fmt.Errorf("DosProtectedResource %s not found", key)
	}
	if !protectedEx.IsValid {
		return nil, errors.New(protectedEx.ErrorMsg)
	}
	dosEx.DosProtected = protectedEx.Obj
	if protectedEx.Obj.Spec.ApDosPolicy != "" {
		policyReference := protectedEx.Obj.Spec.ApDosPolicy
		// if the policy reference does not have a namespace, use the dos protected' namespace
		if !strings.Contains(policyReference, "/") {
			policyReference = protectedEx.Obj.Namespace + "/" + policyReference
		}
		pol, err := ci.getPolicy(policyReference)
		if err != nil {
			return nil, fmt.Errorf("DosProtectedResource references a missing DosPolicy: %w", err)
		}
		dosEx.DosPolicy = pol
	}
	if protectedEx.Obj.Spec.DosSecurityLog != nil && protectedEx.Obj.Spec.DosSecurityLog.ApDosLogConf != "" {
		logConfReference := protectedEx.Obj.Spec.DosSecurityLog.ApDosLogConf
		// if the log conf reference does not have a namespace, use the dos protected' namespace
		if !strings.Contains(logConfReference, "/") {
			logConfReference = protectedEx.Obj.Namespace + "/" + logConfReference
		}
		log, err := ci.getLogConf(logConfReference)
		if err != nil {
			return nil, fmt.Errorf("DosProtectedResource references a missing DosLogConf: %w", err)
		}
		dosEx.DosLogConf = log
	}
	return dosEx, nil
}

func getNsName(defaultNamespace string, name string) string {
	if !strings.Contains(name, "/") {
		return defaultNamespace + "/" + name
	}
	return name
}

// GetDosProtectedThatReferencedDosPolicy gets dos protected resources that mention the given dos policy
func (ci *Configuration) GetDosProtectedThatReferencedDosPolicy(key string) []*v1beta1.DosProtectedResource {
	var protectedResources []*v1beta1.DosProtectedResource
	for _, protectedEx := range ci.dosProtectedResource {
		protected := protectedEx.Obj
		dosPolRef := protected.Spec.ApDosPolicy
		if key == dosPolRef || key == protected.Namespace+"/"+dosPolRef {
			protectedResources = append(protectedResources, protected)
		}
	}
	return protectedResources
}

// GetDosProtectedThatReferencedDosLogConf gets dos protected resources that mention the given dos log conf
func (ci *Configuration) GetDosProtectedThatReferencedDosLogConf(key string) []*v1beta1.DosProtectedResource {
	var protectedResources []*v1beta1.DosProtectedResource
	for _, protectedEx := range ci.dosProtectedResource {
		protected := protectedEx.Obj
		if protected.Spec.DosSecurityLog != nil {
			dosLogConf := protected.Spec.DosSecurityLog.ApDosLogConf
			if key == dosLogConf || key == protected.Namespace+"/"+dosLogConf {
				protectedResources = append(protectedResources, protected)
			}
		}
	}
	return protectedResources
}

// DeletePolicy deletes an App Protect Policy from App Protect Dos Configuration
func (ci *Configuration) DeletePolicy(key string) (changes []Change, problems []Problem) {
	_, has := ci.dosPolicies[key]
	if has {
		changes = append(changes, Change{Op: Delete, Resource: ci.dosPolicies[key]})
		delete(ci.dosPolicies, key)
	}

	protectedResources := ci.GetDosProtectedThatReferencedDosPolicy(key)
	for _, p := range protectedResources {
		proChanges, proProblems := ci.AddOrUpdateDosProtectedResource(p)
		changes = append(changes, proChanges...)
		problems = append(problems, proProblems...)
	}

	return changes, problems
}

// DeleteLogConf deletes an App Protect Dos LogConf from App Protect Dos Configuration
func (ci *Configuration) DeleteLogConf(key string) (changes []Change, problems []Problem) {
	_, has := ci.dosLogConfs[key]
	if has {
		changes = append(changes, Change{Op: Delete, Resource: ci.dosLogConfs[key]})
		delete(ci.dosLogConfs, key)
	}

	protectedResources := ci.GetDosProtectedThatReferencedDosLogConf(key)
	for _, p := range protectedResources {
		proChanges, proProblems := ci.AddOrUpdateDosProtectedResource(p)
		changes = append(changes, proChanges...)
		problems = append(problems, proProblems...)
	}

	return changes, problems
}

// DeleteProtectedResource deletes an App Protect Dos ProtectedResource Configuration
func (ci *Configuration) DeleteProtectedResource(key string) (changes []Change, problems []Problem) {
	if _, has := ci.dosProtectedResource[key]; has {
		change := Change{Op: Delete, Resource: ci.dosProtectedResource[key]}
		delete(ci.dosProtectedResource, key)
		return append(changes, change), problems
	}
	return changes, problems
}

func createAppProtectDosPolicyEx(policyObj *unstructured.Unstructured) (*DosPolicyEx, error) {
	err := validation.ValidateAppProtectDosPolicy(policyObj)
	if err != nil {
		return &DosPolicyEx{
			Obj:      policyObj,
			IsValid:  false,
			ErrorMsg: fmt.Sprintf("failed to store ApDosPolicy: %v", err),
		}, err
	}

	return &DosPolicyEx{
		Obj:     policyObj,
		IsValid: true,
	}, nil
}

func createAppProtectDosLogConfEx(dosLogConfObj *unstructured.Unstructured) (*DosLogConfEx, error) {
	warning, err := validation.ValidateAppProtectDosLogConf(dosLogConfObj)
	if err != nil {
		return &DosLogConfEx{
			Obj:      dosLogConfObj,
			IsValid:  false,
			ErrorMsg: fmt.Sprintf("failed to store ApDosLogconf: %v", err),
		}, err
	}
	if warning != "" {
		return &DosLogConfEx{
			Obj:      dosLogConfObj,
			IsValid:  true,
			ErrorMsg: warning,
		}, nil
	}
	return &DosLogConfEx{
		Obj:     dosLogConfObj,
		IsValid: true,
	}, nil
}

func createDosProtectedResourceEx(protectedConf *v1beta1.DosProtectedResource) (*DosProtectedResourceEx, error) {
	err := validation.ValidateDosProtectedResource(protectedConf)
	if err != nil {
		return &DosProtectedResourceEx{
			Obj:      protectedConf,
			IsValid:  false,
			ErrorMsg: fmt.Sprintf("failed to store DosProtectedResource: %v", err),
		}, err
	}
	return &DosProtectedResourceEx{
		Obj:     protectedConf,
		IsValid: true,
	}, nil
}
