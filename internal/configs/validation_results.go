package configs

import "fmt"

type validationResults struct {
	isError  bool
	warnings []string
}

func newValidationResults() *validationResults {
	return &validationResults{}
}

func (v *validationResults) addWarningf(msgFmt string, args ...interface{}) {
	v.warnings = append(v.warnings, fmt.Sprintf(msgFmt, args...))
}
