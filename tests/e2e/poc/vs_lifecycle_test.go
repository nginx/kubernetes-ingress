//go:build e2e

package poc

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // Ginkgo DSL
)

// Ported from tests/suite/test_virtual_server.py (TestVirtualServer).
var _ = Describe("VirtualServer", Label("vs"), func() {
	for i := range copies {
		It(fmt.Sprintf("routes, updates and removes a VirtualServer #%d", i), func(ctx SpecContext) {
			s := f.NewSandbox(ctx)
			s.Apply(ctx, "common/app/simple/app.yaml")
			s.Apply(ctx, "virtual-server/standard/virtual-server.yaml")

			host := s.Host("virtual-server.example.com")
			for _, p := range []string{"backend1", "backend2"} {
				s.ExpectServedHere(ctx, s.EventuallyStatus(ctx, "http://"+host+"/"+p, 200))
			}

			By("updating host and paths")
			s.Apply(ctx, "virtual-server/standard/virtual-server-updated.yaml")
			newHost := s.Host("virtual-server-up.example.com")
			s.EventuallyStatus(ctx, "http://"+newHost+"/updated-backend1", 200)
			s.EventuallyStatus(ctx, "http://"+newHost+"/updated-backend2", 200)
			s.EventuallyStatus(ctx, "http://"+host+"/backend1", 404)

			By("deleting the VirtualServer")
			s.Delete(ctx, "virtual-server/standard/virtual-server.yaml")
			s.EventuallyStatus(ctx, "http://"+newHost+"/updated-backend1", 404)
		})
	}
})
