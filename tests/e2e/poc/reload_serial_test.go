//go:build e2e

package poc

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // Ginkgo DSL
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck // Gomega DSL
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Ported from tests/suite/test_smoke.py (test_batch_create_reload_count). It asserts on the
// controller-wide reload counter, so it must not overlap with other specs: Serial runs it on
// process 1 after all parallel specs have finished.
var _ = Describe("Reload batching", Serial, Label("serial"), func() {
	It("creates 10 Ingresses with at most 6 reloads", func(ctx SpecContext) {
		const n = 10
		s := f.NewSandbox(ctx)
		s.Apply(ctx, "smoke/smoke-secret.yaml")
		s.Apply(ctx, "common/app/simple/app.yaml")
		s.WaitPodsReady(ctx)
		s.WaitQuiet(ctx)

		before, err := f.ReloadCount(ctx)
		Expect(err).NotTo(HaveOccurred())
		base := s.Load("smoke/standard/smoke-ingress.yaml")[0]
		var hosts []string
		for i := 1; i <= n; i++ {
			o := base.DeepCopy()
			o.SetName(fmt.Sprintf("smoke-ingress-%d", i))
			hosts = append(hosts, s.Host(fmt.Sprintf("smoke-%d.example.com", i)))
			rules, _, _ := unstructured.NestedSlice(o.Object, "spec", "rules")
			rules[0].(map[string]any)["host"] = hosts[i-1]
			Expect(unstructured.SetNestedSlice(o.Object, rules, "spec", "rules")).To(Succeed())
			s.ApplyObject(ctx, o)
		}
		for _, h := range hosts {
			s.EventuallyStatus(ctx, "http://"+h+"/backend1", 200) // tls hosts are not renamed, so these are plain HTTP servers
		}

		after, err := f.ReloadCount(ctx)
		Expect(err).NotTo(HaveOccurred())
		AddReportEntry("reloads", after-before)
		Expect(after - before).To(BeNumerically("<=", n/2+1))
	})
})
