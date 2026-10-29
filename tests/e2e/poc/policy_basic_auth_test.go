//go:build e2e

package poc

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // Ginkgo DSL

	"github.com/nginx/kubernetes-ingress/tests/e2e/framework"
)

// Ported from tests/suite/test_auth_basic_policies.py (VS spec policy), plus detaching the policy.
var _ = Describe("Basic auth policy", Label("policies"), func() {
	for i := range copies {
		It(fmt.Sprintf("enforces and then removes basic auth on a VirtualServer #%d", i), func(ctx SpecContext) {
			s := f.NewSandbox(ctx)
			s.Apply(ctx, "auth-basic-policy/secret/htpasswd-secret-valid.yaml")
			s.Apply(ctx, "auth-basic-policy/policies/auth-basic-policy-valid.yaml")
			s.Apply(ctx, "common/app/simple/app.yaml")
			s.Apply(ctx, "auth-basic-policy/spec/virtual-server-policy-single.yaml")

			url := "http://" + s.Host("virtual-server.example.com") + "/backend1"
			s.EventuallyStatus(ctx, url, 401)
			s.ExpectServedHere(ctx, s.EventuallyStatus(ctx, url, 200, framework.BasicAuth("foo", "bar")))
			s.EventuallyStatus(ctx, url, 401, framework.BasicAuth("foo", "wrong"))

			By("detaching the policy")
			s.Apply(ctx, "virtual-server/standard/virtual-server.yaml")
			s.EventuallyStatus(ctx, url, 200)
		})
	}
})
