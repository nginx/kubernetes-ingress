//go:build e2e

// Package poc validates running NIC e2e specs in parallel against one shared Ingress Controller.
// Run with: make -C tests e2e-poc PROCS=4 COPIES=4
package poc

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck // Ginkgo DSL
	"github.com/onsi/ginkgo/v2/types"
	. "github.com/onsi/gomega" //nolint:revive,staticcheck // Gomega DSL

	"github.com/nginx/kubernetes-ingress/tests/e2e/framework"
)

var (
	f *framework.Framework
	// copies multiplies every parallel spec to generate load on the shared controller.
	copies        = framework.EnvInt("E2E_COPIES", 1)
	reloadsBefore int
)

func TestPoC(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "NIC e2e parallel PoC")
}

var _ = SynchronizedBeforeSuite(func(ctx SpecContext) {
	// Process 1 only: the controller is deployed by `make e2e-poc-deploy`; check it is up.
	fw, err := framework.New()
	Expect(err).NotTo(HaveOccurred())
	Eventually(fw.ICPod).WithContext(ctx).WithTimeout(time.Minute).Should(Not(BeEmpty()))
	reloadsBefore, err = fw.ReloadCount(ctx)
	Expect(err).NotTo(HaveOccurred())
}, func() {
	var err error
	f, err = framework.New()
	Expect(err).NotTo(HaveOccurred())
})

// Runs on process 1 once all processes finish, with every spec's report.
var _ = ReportAfterSuite("PoC summary", func(r Report) {
	passed, failed, connDrops := 0, 0, 0
	for _, sr := range r.SpecReports {
		if sr.LeafNodeType != types.NodeTypeIt {
			continue
		}
		if sr.State.Is(types.SpecStatePassed) {
			passed++
		} else if sr.State.Is(types.SpecStateFailureStates) {
			failed++
		}
		for _, e := range sr.ReportEntries {
			if e.Name == "conn_drops" {
				n, _ := strconv.Atoi(e.StringRepresentation())
				connDrops += n
			}
		}
	}
	reloads := "n/a"
	if f != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if after, err := f.ReloadCount(ctx); err == nil {
			reloads = strconv.Itoa(after - reloadsBefore)
		}
	}
	fmt.Printf("\n=== PoC summary: procs=%d copies=%d wall=%s specs passed=%d failed=%d nginx reloads=%s conn drops=%d ===\n",
		r.SuiteConfig.ParallelTotal, copies, r.RunTime.Round(time.Millisecond), passed, failed, reloads, connDrops)
})
