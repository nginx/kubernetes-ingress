package validation

import (
	"context"
	"io/fs"
	"os"
	"testing"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	"sigs.k8s.io/yaml"
)

// TestCRDsPassAPIServerValidation runs every generated CRD through the API server's own CRD validation,
// which enforces the CEL rule cost budgets (per rule and per CRD) that otherwise only fail at kubectl apply.
func TestCRDsPassAPIServerValidation(t *testing.T) {
	t.Parallel()

	root, err := os.OpenRoot("../../../../config/crd/bases")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	files, err := fs.Glob(root.FS(), "*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no CRD files found in config/crd/bases")
	}

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			t.Parallel()

			data, err := root.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			crdV1 := &apiextensionsv1.CustomResourceDefinition{}
			if err := yaml.UnmarshalStrict(data, crdV1); err != nil {
				t.Fatal(err)
			}
			apiextensionsv1.SetObjectDefaults_CustomResourceDefinition(crdV1)

			crd := &apiextensions.CustomResourceDefinition{}
			if err := apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(crdV1, crd, nil); err != nil {
				t.Fatal(err)
			}

			for _, e := range apiextvalidation.ValidateCustomResourceDefinition(context.Background(), crd) {
				t.Errorf("%v", e)
			}
		})
	}
}
