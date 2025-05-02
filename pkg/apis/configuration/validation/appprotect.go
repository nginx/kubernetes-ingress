package validation

import (
	"fmt"
	"log/slog"
	"strings"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var appProtectPolicyRequiredFields = [][]string{
	{"spec", "policy"},
}

var appProtectLogConfRequiredFields = [][]string{
	{"spec", "content"},
	{"spec", "filter"},
}

var appProtectUserSigRequiredSlices = [][]string{
	{"spec", "signatures"},
}

var appProtectPolicyExtRefs = [][]string{
	{"spec", "policy", "modificationsReference"},
	{"spec", "policy", "blockingSettingReference"},
	{"spec", "policy", "signatureSettingReference"},
	{"spec", "policy", "serverTechnologyReference"},
	{"spec", "policy", "headerReference"},
	{"spec", "policy", "cookieReference"},
	{"spec", "policy", "dataGuardReference"},
	{"spec", "policy", "filetypeReference"},
	{"spec", "policy", "methodReference"},
	{"spec", "policy", "generalReference"},
	{"spec", "policy", "parameterReference"},
	{"spec", "policy", "sensitiveParameterReference"},
	{"spec", "policy", "jsonProfileReference"},
	{"spec", "policy", "xmlProfileReference"},
	{"spec", "policy", "whitelistIpReference"},
	{"spec", "policy", "responsePageReference"},
	{"spec", "policy", "characterSetReference"},
	{"spec", "policy", "cookieSettingsReference"},
	{"spec", "policy", "headerSettingsReference"},
	{"spec", "policy", "jsonValidationFileReference"},
	{"spec", "policy", "xmlValidationFileReference"},
	{"spec", "policy", "signatureSetReference"},
	{"spec", "policy", "signatureReference"},
	{"spec", "policy", "urlReference"},
	{"spec", "policy", "threatCampaignReference"},
}

// ValidateAppProtectPolicy validates Policy resource
func ValidateAppProtectPolicy(policy *unstructured.Unstructured, l *slog.Logger) error {
	polName := policy.GetName()

	err := ValidateRequiredFields(policy, appProtectPolicyRequiredFields)
	if err != nil {
		return fmt.Errorf("error validating App Protect Policy %v: %w", polName, err)
	}

	extRefs, err := checkForExtRefs(policy)
	if err != nil {
		return fmt.Errorf("error validating App Protect Policy %v: %w", polName, err)
	}

	if len(extRefs) > 0 {
		for _, ref := range extRefs {
			nl.Debugf(l, "Warning: Field %s (External reference) is Deprecated.", ref)
		}
	}

	return nil
}

// ValidateAppProtectLogConf validates LogConfiguration resource
func ValidateAppProtectLogConf(logConf *unstructured.Unstructured) error {
	lcName := logConf.GetName()
	err := ValidateRequiredFields(logConf, appProtectLogConfRequiredFields)
	if err != nil {
		return fmt.Errorf("error validating App Protect Log Configuration %v: %w", lcName, err)
	}

	return nil
}

// ValidateAppProtectUserSig validates the app protect user sig.
func ValidateAppProtectUserSig(userSig *unstructured.Unstructured) error {
	sigName := userSig.GetName()
	err := ValidateRequiredSlices(userSig, appProtectUserSigRequiredSlices)
	if err != nil {
		return fmt.Errorf("error validating App Protect User Signature %v: %w", sigName, err)
	}

	return nil
}

func checkForExtRefs(policy *unstructured.Unstructured) ([]string, error) {
	polName := policy.GetName()
	out := []string{}
	for _, ref := range appProtectPolicyExtRefs {
		_, found, err := unstructured.NestedFieldNoCopy(policy.Object, ref...)
		if err != nil {
			return out, fmt.Errorf("error validating App Protect Policy %v: %w", polName, err)
		}
		if found {
			out = append(out, strings.Join(ref, "."))
		}
	}
	return out, nil
}
