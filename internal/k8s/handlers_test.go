package k8s

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestAreResourcesDifferent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		oldR, newR *unstructured.Unstructured
		expected   bool
		expectErr  error
		msg        string
	}{
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": true, // wrong type
				},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			expected:  false,
			expectErr: errors.New(`.spec accessor error: true is of the type bool, expected map[string]interface{}`),
			msg:       "invalid old resource",
		},
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": true, // wrong type
				},
			},
			expected:  false,
			expectErr: errors.New(`.spec accessor error: true is of the type bool, expected map[string]interface{}`),
			msg:       "invalid new resource",
		},
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			expected:  false,
			expectErr: errors.New(`spec has unexpected format`),
			msg:       "new resource with missing spec",
		},
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"field": "a",
					},
				},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"field": "a",
					},
				},
			},
			expected:  false,
			expectErr: nil,
			msg:       "equal resources",
		},
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"field": "a",
					},
				},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"field": "b",
					},
				},
			},
			expected:  true,
			expectErr: nil,
			msg:       "not equal resources",
		},
		{
			oldR: &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			newR: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"field": "b",
					},
				},
			},
			expected:  true,
			expectErr: nil,
			msg:       "not equal resources with first resource missing spec",
		},
	}

	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	for _, test := range tests {
		result, err := areResourcesDifferent(l, test.oldR, test.newR)
		if result != test.expected {
			t.Errorf("areResourcesDifferent() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
		if test.expectErr != nil {
			if err == nil {
				t.Errorf("areResourcesDifferent() returned no error for the case of %s", test.msg)
			} else if test.expectErr.Error() != err.Error() {
				t.Errorf("areResourcesDifferent() returned an unexpected error '%v' for the case of %s", err, test.msg)
			}
		}
		if test.expectErr == nil && err != nil {
			t.Errorf("areResourcesDifferent() returned unexpected error %v for the case of %s", err, test.msg)
		}
	}
}
