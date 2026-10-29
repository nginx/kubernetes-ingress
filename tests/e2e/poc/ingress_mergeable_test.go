//go:build e2e

package poc

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // Ginkgo DSL
)

// Ported from tests/suite/test_smoke.py (mergeable variant of test_response_code_200_and_server_name).
var _ = Describe("Mergeable Ingress", Label("ingresses"), func() {
	for i := range copies {
		It(fmt.Sprintf("serves master and minions over TLS #%d", i), func(ctx SpecContext) {
			s := f.NewSandbox(ctx)
			s.Apply(ctx, "smoke/smoke-secret.yaml")
			s.Apply(ctx, "common/app/simple/app.yaml")
			s.Apply(ctx, "smoke/mergeable/smoke-ingress.yaml")

			host := s.Host("smoke.example.com")
			for _, p := range []string{"backend1", "backend2"} {
				s.ExpectServedHere(ctx, s.EventuallyStatus(ctx, "https://"+host+"/"+p, 200))
			}
		})
	}
})
