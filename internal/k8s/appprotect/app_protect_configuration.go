package appprotect

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/nginx/kubernetes-ingress/internal/k8s/appprotectcommon"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/pkg/apis/configuration/validation"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const timeLayout = time.RFC3339

// reasons for invalidity
const (
	failedValidationErrorMsg = "validation failed"
	missingUserSigErrorMsg   = "policy has unsatisfied signature requirements"
	duplicatedTagsErrorMsg   = "duplicate tag set"
	invalidTimestampErrorMsg = "invalid timestamp"
)

var (
	// PolicyGVR is the group version resource of the appprotect policy
	PolicyGVR = schema.GroupVersionResource{
		Group:    "appprotect.f5.com",
		Version:  "v1beta1",
		Resource: "appolicies",
	}
	// PolicyGVK is the group version kind of the appprotect policy
	PolicyGVK = schema.GroupVersionKind{
		Group:   "appprotect.f5.com",
		Version: "v1beta1",
		Kind:    "APPolicy",
	}

	// LogConfGVR is the group version resource of the appprotect policy
	LogConfGVR = schema.GroupVersionResource{
		Group:    "appprotect.f5.com",
		Version:  "v1beta1",
		Resource: "aplogconfs",
	}
	// LogConfGVK is the group version kind of the appprotect policy
	LogConfGVK = schema.GroupVersionKind{
		Group:   "appprotect.f5.com",
		Version: "v1beta1",
		Kind:    "APLogConf",
	}

	// UserSigGVR is the group version resource of the appprotect policy
	UserSigGVR = schema.GroupVersionResource{
		Group:    "appprotect.f5.com",
		Version:  "v1beta1",
		Resource: "apusersigs",
	}
	// UserSigGVK is the group version kind of the appprotect policy
	UserSigGVK = schema.GroupVersionKind{
		Group:   "appprotect.f5.com",
		Version: "v1beta1",
		Kind:    "APUserSig",
	}
)

// UserSigChange holds resources that are affected by changes in UserSigs
type UserSigChange struct {
	PolicyDeletions     []*unstructured.Unstructured
	PolicyAddsOrUpdates []*unstructured.Unstructured
	UserSigs            []*unstructured.Unstructured
}

// Operation defines an operation to perform for an App Protect resource.
type Operation int

const (
	// Delete the config of the resource
	Delete Operation = iota
	// AddOrUpdate the config of the resource
	AddOrUpdate
)

// Change represents a change in an App Protect resource
type Change struct {
	// Op is an operation that needs be performed on the resource.
	Op Operation
	// Resource is the target resource.
	Resource interface{}
}

// Problem represents a problem with an App Protect resource
type Problem struct {
	// Object is a configuration object.
	Object *unstructured.Unstructured
	// Reason tells the reason. It matches the reason in the events of our configuration objects.
	Reason string
	// Message gives the details about the problem. It matches the message in the events of our configuration objects.
	Message string
}

// Configuration configures App Protect resources that the Ingress Controller uses.
type Configuration interface {
	AddOrUpdatePolicy(policyObj *unstructured.Unstructured) (changes []Change, problems []Problem)
	AddOrUpdateLogConf(logConfObj *unstructured.Unstructured) (changes []Change, problems []Problem)
	AddOrUpdateUserSig(userSigObj *unstructured.Unstructured) (change UserSigChange, problems []Problem)
	GetAppResource(kind, key string) (*unstructured.Unstructured, error)
	DeletePolicy(key string) (changes []Change, problems []Problem)
	DeleteLogConf(key string) (changes []Change, problems []Problem)
	DeleteUserSig(key string) (change UserSigChange, problems []Problem)
}

// ConfigurationImpl holds representations of App Protect cluster resources
type ConfigurationImpl struct {
	Policies map[string]*PolicyEx
	LogConfs map[string]*LogConfEx
	UserSigs map[string]*UserSigEx
	Logger   *slog.Logger
}

// NewConfiguration creates a new App Protect Configuration
func NewConfiguration(l *slog.Logger) Configuration {
	return newConfigurationImpl(l)
}

// NewConfiguration creates a new App Protect Configuration
func newConfigurationImpl(l *slog.Logger) *ConfigurationImpl {
	return &ConfigurationImpl{
		Policies: make(map[string]*PolicyEx),
		LogConfs: make(map[string]*LogConfEx),
		UserSigs: make(map[string]*UserSigEx),
		Logger:   l,
	}
}

// PolicyEx represents an App Protect policy cluster resource
type PolicyEx struct {
	Obj           *unstructured.Unstructured
	SignatureReqs []SignatureReq
	IsValid       bool
	ErrorMsg      string
}

func (pol *PolicyEx) setInvalid(reason string) {
	pol.IsValid = false
	pol.ErrorMsg = reason
}

func (pol *PolicyEx) setValid() {
	pol.IsValid = true
	pol.ErrorMsg = ""
}

// SignatureReq describes a signature that is required by the policy
type SignatureReq struct {
	Tag      string
	RevTimes *RevTimes
}

// RevTimes are requirements for signature revision time
type RevTimes struct {
	MinRevTime *time.Time
	MaxRevTime *time.Time
}

// LogConfEx represents an App Protect Log Configuration cluster resource
type LogConfEx struct {
	Obj      *unstructured.Unstructured
	IsValid  bool
	ErrorMsg string
}

// UserSigEx represents an App Protect User Defined Signature cluster resource
type UserSigEx struct {
	Obj      *unstructured.Unstructured
	Tag      string
	RevTime  *time.Time
	IsValid  bool
	ErrorMsg string
}

func (sig *UserSigEx) setInvalid(reason string) {
	sig.IsValid = false
	sig.ErrorMsg = reason
}

func (sig *UserSigEx) setValid() {
	sig.IsValid = true
	sig.ErrorMsg = ""
}

type appProtectUserSigSlice []*UserSigEx

func (s appProtectUserSigSlice) Len() int {
	return len(s)
}

func (s appProtectUserSigSlice) Less(i, j int) bool {
	if s[i].Obj.GetCreationTimestamp().Time.Equal(s[j].Obj.GetCreationTimestamp().Time) {
		return s[i].Obj.GetUID() > s[j].Obj.GetUID()
	}
	return s[i].Obj.GetCreationTimestamp().Time.Before(s[j].Obj.GetCreationTimestamp().Time)
}

func (s appProtectUserSigSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func createAppProtectPolicyEx(policyObj *unstructured.Unstructured, l *slog.Logger) (*PolicyEx, error) {
	err := validation.ValidateAppProtectPolicy(policyObj, l)
	if err != nil {
		errMsg := fmt.Sprintf("Error validating policy %s: %v", policyObj.GetName(), err)
		return &PolicyEx{Obj: policyObj, IsValid: false, ErrorMsg: failedValidationErrorMsg}, errors.New(errMsg)
	}
	sigReqs := []SignatureReq{}
	// Check if policy has signature requirement (revision timestamp) and map them to tags
	list, found, err := unstructured.NestedSlice(policyObj.Object, "spec", "policy", "signature-requirements")
	if err != nil {
		errMsg := fmt.Sprintf("Error retrieving Signature requirements from %s: %v", policyObj.GetName(), err)
		return &PolicyEx{Obj: policyObj, IsValid: false, ErrorMsg: failedValidationErrorMsg}, errors.New(errMsg)
	}
	if found {
		for _, req := range list {
			requirement := req.(map[string]interface{})
			if reqTag, ok := requirement["tag"]; ok {
				timeReq, err := buildRevTimes(requirement)
				if err != nil {
					errMsg := fmt.Sprintf("Error creating time requirements from %s: %v", policyObj.GetName(), err)
					return &PolicyEx{Obj: policyObj, IsValid: false, ErrorMsg: invalidTimestampErrorMsg}, errors.New(errMsg)
				}
				sigReqs = append(sigReqs, SignatureReq{Tag: reqTag.(string), RevTimes: &timeReq})
			}
		}
	}
	return &PolicyEx{
		Obj:           policyObj,
		SignatureReqs: sigReqs,
		IsValid:       true,
	}, nil
}

func buildRevTimes(requirement map[string]interface{}) (RevTimes, error) {
	timeReq := RevTimes{}
	if minRev, ok := requirement["minRevisionDatetime"]; ok {
		minRevTime, err := time.Parse(timeLayout, minRev.(string))
		if err != nil {
			errMsg := fmt.Sprintf("Error Parsing time from minRevisionDatetime %v", err)
			return timeReq, errors.New(errMsg)
		}
		timeReq.MinRevTime = &minRevTime
	}
	if maxRev, ok := requirement["maxRevisionDatetime"]; ok {
		maxRevTime, err := time.Parse(timeLayout, maxRev.(string))
		if err != nil {
			errMsg := fmt.Sprintf("Error Parsing time from maxRevisionDatetime  %v", err)
			return timeReq, errors.New(errMsg)
		}
		timeReq.MaxRevTime = &maxRevTime
	}
	return timeReq, nil
}

func createAppProtectLogConfEx(logConfObj *unstructured.Unstructured) (*LogConfEx, error) {
	err := validation.ValidateAppProtectLogConf(logConfObj)
	if err != nil {
		return &LogConfEx{
			Obj:      logConfObj,
			IsValid:  false,
			ErrorMsg: failedValidationErrorMsg,
		}, err
	}
	return &LogConfEx{
		Obj:     logConfObj,
		IsValid: true,
	}, nil
}

func createAppProtectUserSigEx(userSigObj *unstructured.Unstructured) (*UserSigEx, error) {
	sTag := ""
	err := validation.ValidateAppProtectUserSig(userSigObj)
	if err != nil {
		errMsg := failedValidationErrorMsg
		return &UserSigEx{Obj: userSigObj, IsValid: false, Tag: sTag, ErrorMsg: errMsg}, errors.New(errMsg)
	}
	// Previous validation ensures there will be no errors
	tag, found, _ := unstructured.NestedString(userSigObj.Object, "spec", "tag")
	if found {
		sTag = tag
	}
	revTimeString, revTimeFound, _ := unstructured.NestedString(userSigObj.Object, "spec", "revisionDatetime")
	if revTimeFound {
		revTime, err := time.Parse(timeLayout, revTimeString)
		if err != nil {
			errMsg := invalidTimestampErrorMsg
			return &UserSigEx{Obj: userSigObj, IsValid: false, ErrorMsg: errMsg}, errors.New(errMsg)
		}
		return &UserSigEx{
			Obj:     userSigObj,
			Tag:     sTag,
			RevTime: &revTime,
			IsValid: true,
		}, nil
	}
	return &UserSigEx{
		Obj:     userSigObj,
		Tag:     sTag,
		IsValid: true,
	}, nil
}

func isReqSatisfiedByUserSig(sigReq SignatureReq, sig *UserSigEx) bool {
	if sig.Tag == "" || sig.Tag != sigReq.Tag {
		return false
	}
	if sigReq.RevTimes == nil || sig.RevTime == nil {
		return sig.Tag == sigReq.Tag
	}
	if sigReq.RevTimes.MinRevTime != nil && sigReq.RevTimes.MaxRevTime != nil {
		return sig.RevTime.Before(*sigReq.RevTimes.MaxRevTime) && sig.RevTime.After(*sigReq.RevTimes.MinRevTime)
	}
	if sigReq.RevTimes.MaxRevTime != nil && sig.RevTime.Before(*sigReq.RevTimes.MaxRevTime) {
		return true
	}
	if sigReq.RevTimes.MinRevTime != nil && sig.RevTime.After(*sigReq.RevTimes.MinRevTime) {
		return true
	}
	return false
}

func isReqSatisfiedByUserSigs(sigReq SignatureReq, sigs map[string]*UserSigEx) bool {
	for _, sig := range sigs {
		if isReqSatisfiedByUserSig(sigReq, sig) && sig.IsValid {
			return true
		}
	}
	return false
}

func (ci *ConfigurationImpl) verifyPolicyAgainstUserSigs(policy *PolicyEx) bool {
	for _, sigreq := range policy.SignatureReqs {
		if !isReqSatisfiedByUserSigs(sigreq, ci.UserSigs) {
			return false
		}
	}
	return true
}

// AddOrUpdatePolicy adds or updates an App Protect Policy to App Protect Configuration
func (ci *ConfigurationImpl) AddOrUpdatePolicy(policyObj *unstructured.Unstructured) (changes []Change, problems []Problem) {
	resNsName := appprotectcommon.GetNsName(policyObj)
	policy, err := createAppProtectPolicyEx(policyObj, ci.Logger)
	if err != nil {
		ci.Policies[resNsName] = policy
		return append(changes, Change{Op: Delete, Resource: policy}),
			append(problems, Problem{Object: policyObj, Reason: nl.EventReasonRejected, Message: err.Error()})
	}
	if ci.verifyPolicyAgainstUserSigs(policy) {
		ci.Policies[resNsName] = policy
		return append(changes, Change{Op: AddOrUpdate, Resource: policy}), problems
	}
	policy.IsValid = false
	policy.ErrorMsg = missingUserSigErrorMsg
	ci.Policies[resNsName] = policy
	return append(changes, Change{Op: Delete, Resource: policy}),
		append(problems, Problem{Object: policyObj, Reason: nl.EventReasonRejected, Message: missingUserSigErrorMsg})
}

// AddOrUpdateLogConf adds or updates App Protect Log Configuration to App Protect Configuration
func (ci *ConfigurationImpl) AddOrUpdateLogConf(logconfObj *unstructured.Unstructured) (changes []Change, problems []Problem) {
	resNsName := appprotectcommon.GetNsName(logconfObj)
	logConf, err := createAppProtectLogConfEx(logconfObj)
	ci.LogConfs[resNsName] = logConf
	if err != nil {
		return append(changes, Change{Op: Delete, Resource: logConf}),
			append(problems, Problem{Object: logconfObj, Reason: nl.EventReasonRejected, Message: err.Error()})
	}
	return append(changes, Change{Op: AddOrUpdate, Resource: logConf}), problems
}

// AddOrUpdateUserSig adds or updates App Protect User Defined Signature to App Protect Configuration
func (ci *ConfigurationImpl) AddOrUpdateUserSig(userSigObj *unstructured.Unstructured) (change UserSigChange, problems []Problem) {
	resNsName := appprotectcommon.GetNsName(userSigObj)
	userSig, err := createAppProtectUserSigEx(userSigObj)
	ci.UserSigs[resNsName] = userSig
	if err != nil {
		problems = append(problems, Problem{Object: userSigObj, Reason: nl.EventReasonRejected, Message: err.Error()})
	}
	change.UserSigs = append(change.UserSigs, userSigObj)
	ci.buildUserSigChangeAndProblems(&problems, &change)

	return change, problems
}

// GetAppResource returns a pointer to an App Protect resource
func (ci *ConfigurationImpl) GetAppResource(kind, key string) (*unstructured.Unstructured, error) {
	switch kind {
	case PolicyGVK.Kind:
		if obj, ok := ci.Policies[key]; ok {
			if obj.IsValid {
				return obj.Obj, nil
			}
			return nil, errors.New(obj.ErrorMsg)
		}
		return nil, fmt.Errorf("app protect Policy %s not found", key)
	case LogConfGVK.Kind:
		if obj, ok := ci.LogConfs[key]; ok {
			if obj.IsValid {
				return obj.Obj, nil
			}
			return nil, errors.New(obj.ErrorMsg)
		}
		return nil, fmt.Errorf("app protect LogConf %s not found", key)
	case UserSigGVK.Kind:
		if obj, ok := ci.UserSigs[key]; ok {
			if obj.IsValid {
				return obj.Obj, nil
			}
			return nil, errors.New(obj.ErrorMsg)
		}
		return nil, fmt.Errorf("app protect UserSig %s not found", key)
	}
	return nil, fmt.Errorf("unknown app protect resource kind %s", kind)
}

// DeletePolicy deletes an App Protect Policy from App Protect Configuration
func (ci *ConfigurationImpl) DeletePolicy(key string) (changes []Change, problems []Problem) {
	if _, has := ci.Policies[key]; has {
		change := Change{Op: Delete, Resource: ci.Policies[key]}
		delete(ci.Policies, key)
		return append(changes, change), problems
	}
	return changes, problems
}

// DeleteLogConf deletes an App Protect Log Configuration from App Protect Configuration
func (ci *ConfigurationImpl) DeleteLogConf(key string) (changes []Change, problems []Problem) {
	if _, has := ci.LogConfs[key]; has {
		change := Change{Op: Delete, Resource: ci.LogConfs[key]}
		delete(ci.LogConfs, key)
		return append(changes, change), problems
	}
	return changes, problems
}

// DeleteUserSig deletes an App Protect User Defined Signature from App Protect Configuration
func (ci *ConfigurationImpl) DeleteUserSig(key string) (change UserSigChange, problems []Problem) {
	if _, has := ci.UserSigs[key]; has {
		change.UserSigs = append(change.UserSigs, ci.UserSigs[key].Obj)
		delete(ci.UserSigs, key)
		ci.buildUserSigChangeAndProblems(&problems, &change)
	}
	return change, problems
}

func (ci *ConfigurationImpl) detectDuplicateTags() (outcome [][]*UserSigEx) {
	tmp := make(map[string][]*UserSigEx)
	for _, sig := range ci.UserSigs {
		if val, has := tmp[sig.Tag]; has {
			if sig.ErrorMsg != failedValidationErrorMsg {
				tmp[sig.Tag] = append(val, sig)
			}
		} else {
			if sig.ErrorMsg != failedValidationErrorMsg {
				tmp[sig.Tag] = []*UserSigEx{sig}
			}
		}
	}
	for key, vals := range tmp {
		if key != "" {
			outcome = append(outcome, vals)
		}
	}
	return outcome
}

// reconcileUserSigs verifies if tags defined in uds resources are unique
func (ci *ConfigurationImpl) reconcileUserSigs() (changes []Change, problems []Problem) {
	dupTag := ci.detectDuplicateTags()
	for _, sigs := range dupTag {
		sort.Sort(appProtectUserSigSlice(sigs))
		winner := sigs[0]
		if !winner.IsValid {
			winner.setValid()
			change := Change{Op: AddOrUpdate, Resource: winner}
			changes = append(changes, change)
		}
		for _, sig := range sigs[1:] {
			if sig.IsValid {
				sig.setInvalid(duplicatedTagsErrorMsg)
				looserProblem := Problem{Object: sig.Obj, Reason: nl.EventReasonRejected, Message: duplicatedTagsErrorMsg}
				looserChange := Change{Op: Delete, Resource: sig}
				changes = append(changes, looserChange)
				problems = append(problems, looserProblem)
			}
		}
	}
	return changes, problems
}

func (ci *ConfigurationImpl) verifyPolicies() (changes []Change, problems []Problem) {
	for _, pol := range ci.Policies {
		if !pol.IsValid && pol.ErrorMsg == missingUserSigErrorMsg {
			if ci.verifyPolicyAgainstUserSigs(pol) {
				pol.setValid()
				change := Change{Op: AddOrUpdate, Resource: pol}
				changes = append(changes, change)
			}
		}
		if pol.IsValid {
			if !ci.verifyPolicyAgainstUserSigs(pol) {
				pol.setInvalid(missingUserSigErrorMsg)
				polProb := Problem{Object: pol.Obj, Reason: nl.EventReasonRejected, Message: missingUserSigErrorMsg}
				polCh := Change{Op: Delete, Resource: pol}
				changes = append(changes, polCh)
				problems = append(problems, polProb)
			}
		}
	}
	return changes, problems
}

func (ci *ConfigurationImpl) getAllUserSigObjects() []*unstructured.Unstructured {
	out := []*unstructured.Unstructured{}
	for _, uds := range ci.UserSigs {
		if uds.IsValid {
			out = append(out, uds.Obj)
		}
	}
	return out
}

func (ci *ConfigurationImpl) buildUserSigChangeAndProblems(problems *[]Problem, udschange *UserSigChange) {
	reconChanges, reconProblems := ci.reconcileUserSigs()
	verChanges, verProblems := ci.verifyPolicies()
	*problems = append(*problems, reconProblems...)
	*problems = append(*problems, verProblems...)
	reconChanges = append(reconChanges, verChanges...)
	for _, cha := range reconChanges {
		switch impl := cha.Resource.(type) {
		case *PolicyEx:
			if cha.Op == Delete {
				udschange.PolicyDeletions = append(udschange.PolicyDeletions, impl.Obj)
			}
			if cha.Op == AddOrUpdate {
				udschange.PolicyAddsOrUpdates = append(udschange.PolicyAddsOrUpdates, impl.Obj)
			}
		case *UserSigEx:
			continue
		}
	}
	udschange.UserSigs = ci.getAllUserSigObjects()
}

// FakeConfiguration holds representations of fake App Protect cluster resources
type FakeConfiguration struct {
	Policies map[string]*PolicyEx
	LogConfs map[string]*LogConfEx
	UserSigs map[string]*UserSigEx
}

// NewFakeConfiguration creates a new App Protect Configuration
func NewFakeConfiguration() Configuration {
	return &FakeConfiguration{
		Policies: make(map[string]*PolicyEx),
		LogConfs: make(map[string]*LogConfEx),
		UserSigs: make(map[string]*UserSigEx),
	}
}

// AddOrUpdatePolicy adds or updates an App Protect Policy to App Protect Configuration
func (fc *FakeConfiguration) AddOrUpdatePolicy(policyObj *unstructured.Unstructured) (changes []Change, problems []Problem) {
	resNsName := appprotectcommon.GetNsName(policyObj)
	policy := &PolicyEx{
		Obj:     policyObj,
		IsValid: true,
	}
	fc.Policies[resNsName] = policy
	return changes, problems
}

// AddOrUpdateLogConf adds or updates App Protect Log Configuration to App Protect Configuration
func (fc *FakeConfiguration) AddOrUpdateLogConf(logConfObj *unstructured.Unstructured) (changes []Change, problems []Problem) {
	resNsName := appprotectcommon.GetNsName(logConfObj)
	logConf := &LogConfEx{
		Obj:     logConfObj,
		IsValid: true,
	}
	fc.LogConfs[resNsName] = logConf
	return changes, problems
}

// AddOrUpdateUserSig adds or updates App Protect User Defined Signature to App Protect Configuration
func (fc *FakeConfiguration) AddOrUpdateUserSig(_ *unstructured.Unstructured) (change UserSigChange, problems []Problem) {
	return change, problems
}

// GetAppResource returns a pointer to an App Protect resource
func (fc *FakeConfiguration) GetAppResource(kind, key string) (*unstructured.Unstructured, error) {
	switch kind {
	case PolicyGVK.Kind:
		if obj, ok := fc.Policies[key]; ok {
			return obj.Obj, nil
		}
		return nil, fmt.Errorf("app protect Policy %s not found", key)
	case LogConfGVK.Kind:
		if obj, ok := fc.LogConfs[key]; ok {
			return obj.Obj, nil
		}
		return nil, fmt.Errorf("app protect LogConf %s not found", key)
	}
	return nil, fmt.Errorf("unknown app protect resource kind %s", kind)
}

// DeletePolicy deletes an App Protect Policy from App Protect Configuration
func (fc *FakeConfiguration) DeletePolicy(_ string) (changes []Change, problems []Problem) {
	return changes, problems
}

// DeleteLogConf deletes an App Protect Log Configuration from App Protect Configuration
func (fc *FakeConfiguration) DeleteLogConf(_ string) (changes []Change, problems []Problem) {
	return changes, problems
}

// DeleteUserSig deletes an App Protect User Defined Signature from App Protect Configuration
func (fc *FakeConfiguration) DeleteUserSig(_ string) (change UserSigChange, problems []Problem) {
	return change, problems
}
