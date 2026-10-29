//go:build e2e

package poc

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // Ginkgo DSL
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck // Gomega DSL
)

// Ported from tests/suite/test_virtual_server_split_traffic.py (test_several_requests).
var _ = Describe("VirtualServer traffic split", Label("vs"), func() {
	for i := range copies {
		It(fmt.Sprintf("splits traffic 90/10 #%d", i), func(ctx SpecContext) {
			s := f.NewSandbox(ctx)
			s.Apply(ctx, "common/app/split/app.yaml")
			s.Apply(ctx, "virtual-server-split-traffic/standard/virtual-server.yaml")
			s.WaitPodsReady(ctx)

			url := "http://" + s.Host("virtual-server-splitted.example.com") + "/backends"
			s.ExpectServedHere(ctx, s.EventuallyStatus(ctx, url, 200))

			const samples = 100
			v1 := 0
			for range samples {
				body := s.EventuallyStatus(ctx, url, 200)
				switch {
				case strings.Contains(body, "backend1-v1"):
					v1++
				case !strings.Contains(body, "backend1-v2"):
					Fail("unexpected response: " + body)
				}
			}
			Expect(float64(v1)/samples).To(BeNumerically("~", 0.9, 0.2), "share of backend1-v1")
		})
	}
})
