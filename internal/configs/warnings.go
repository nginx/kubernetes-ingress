package configs

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
)

// Warnings stores a list of warnings for a given runtime k8s object in a map
type Warnings map[runtime.Object][]string

func (w Warnings) String() string {
	var str string
	for _, warnings := range w {
		for _, warning := range warnings {
			str += fmt.Sprintf("%s\n", warning)
		}
	}
	return str
}

func newWarnings() Warnings {
	return make(map[runtime.Object][]string)
}

// Add adds new Warnings to the map
func (w Warnings) Add(warnings Warnings) {
	for k, v := range warnings {
		w[k] = v
	}
}

// AddWarningf Adds a warning for the specified object using the provided format and arguments.
func (w Warnings) AddWarningf(obj runtime.Object, msgFmt string, args ...interface{}) {
	w[obj] = append(w[obj], fmt.Sprintf(msgFmt, args...))
}

// AddWarning Adds a warning for the specified object.
func (w Warnings) AddWarning(obj runtime.Object, msg string) {
	w[obj] = append(w[obj], msg)
}
