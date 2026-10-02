package k8s

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// configuratorCallAllowlist is the exhaustive set of Configurator methods that
// LoadBalancerController.syncEndpointSlices is permitted to call — either
// directly, or via its early-return branch for the controller's own Service
// into updateNumberOfIngressControllerReplicas.
//
// This set matters because every task Kind other than endpointslice forces a
// reload at batch end (sync() sets enableBatchReload for anything that isn't
// endpointslice — see controller.go), but an endpointslice-only batch no
// longer does, since https://github.com/nginx/kubernetes-ingress/issues/7778.
// For that batch shape, ReloadForBatchUpdates relies entirely on
// Configurator.reloadDeferred to know a written-but-unapplied config is
// pending (see the invariant documented on Configurator.deferReload). Every
// entry on this list has been checked to either honor that invariant on its
// own error paths (the four UpdateEndpoints*/three AddOrUpdate* write paths)
// or to not need to (the two state-only accessors, which never write NGINX
// config).
//
// If this test fails because it found a method NOT on this list: a new
// Configurator call was added somewhere reachable from an endpointslice-only
// batch. Before adding it to the allowlist, verify it marks the batch dirty
// (via Configurator.deferReload, or by reaching Configurator.Reload itself)
// on every error path that can follow a successful partial write — then add
// it here with a comment explaining why it's safe.
//
// If it fails because an entry here was NOT found: the call was removed or
// renamed. Update this list to match — don't leave stale entries that make
// the allowlist wider than what's actually reachable.
//
// Limitation: this is a syntactic, single-hop check (parses the two source
// files, matches `*.configurator.<Method>(...)` call expressions). It does
// NOT perform call-graph analysis, so a new Configurator call added behind an
// intermediate helper function (rather than directly in these two functions)
// will not be detected. Full interprocedural reachability analysis was judged
// out of proportion to the risk here; this tripwire catches the exact shape
// of the historical regression (a direct new call added to one of these two
// functions) without that cost.
var configuratorCallAllowlist = map[string]bool{
	// Reached directly from syncEndpointSlices for ordinary (non-controller)
	// resources. All four already mark the batch dirty on error via
	// Configurator.deferReload.
	"UpdateEndpoints":                    true,
	"UpdateEndpointsMergeableIngress":    true,
	"UpdateEndpointsForVirtualServers":   true,
	"UpdateEndpointsForTransportServers": true,

	// Reached via syncEndpointSlices's early return for the controller's own
	// Service, into updateNumberOfIngressControllerReplicas. All three mark
	// the batch dirty on error via Configurator.deferReload.
	"AddOrUpdateIngress":          true,
	"AddOrUpdateMergeableIngress": true,
	"AddOrUpdateVirtualServer":    true,

	// State-only accessors used by updateNumberOfIngressControllerReplicas to
	// detect a replica-count change. Neither writes NGINX config, so neither
	// has a Reload()/deferReload() obligation.
	"GetIngressControllerReplicas": true,
	"SetIngressControllerReplicas": true,
}

// TestEndpointsliceReachableConfiguratorCallsAreKnown is a tripwire, not a
// correctness proof: it fails whenever the set of Configurator methods
// reachable from an endpointslice-only batch changes, forcing a human to
// re-examine the invariant on configuratorCallAllowlist above rather than
// relying on someone noticing during review that a new call was added deep in
// a cross-package call chain (syncEndpointSlices lives in internal/k8s;
// Configurator.deferReload lives in internal/configs).
// collectConfiguratorCalls walks node and records the method name of every
// call expression matching `<anything>.configurator.<Method>(...)` into
// found. The outer selector's base is deliberately unchecked (not pinned to
// e.g. "lbc") so renaming the receiver can't silently defeat this check.
func collectConfiguratorCalls(node ast.Node, found map[string]bool) {
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		outer, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		inner, ok := outer.X.(*ast.SelectorExpr)
		if !ok || inner.Sel.Name != "configurator" {
			return true
		}
		found[outer.Sel.Name] = true
		return true
	})
}

// findFuncDecl returns the top-level function declaration named name in
// file, or nil if it isn't found (e.g. after a rename).
func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == name {
			return fd
		}
	}
	return nil
}

// diffConfiguratorCalls reports the asymmetric differences between found and
// configuratorCallAllowlist, both sorted for deterministic failure messages.
func diffConfiguratorCalls(found map[string]bool) (unexpected, missing []string) {
	for method := range found {
		if !configuratorCallAllowlist[method] {
			unexpected = append(unexpected, method)
		}
	}
	for method := range configuratorCallAllowlist {
		if !found[method] {
			missing = append(missing, method)
		}
	}
	sort.Strings(unexpected)
	sort.Strings(missing)
	return unexpected, missing
}

func TestEndpointsliceReachableConfiguratorCallsAreKnown(t *testing.T) {
	fset := token.NewFileSet()
	found := map[string]bool{}

	epFile, err := parser.ParseFile(fset, "endpoint_slice.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing endpoint_slice.go: %v", err)
	}
	// Scoped to syncEndpointSlices itself (not the whole file): a Configurator call
	// added to an unrelated function in this file — e.g. createEndpointSliceHandlers
	// or addEndpointSliceHandler, neither reachable from an endpointslice-only batch —
	// must not trip this tripwire.
	syncFn := findFuncDecl(epFile, "syncEndpointSlices")
	if syncFn == nil {
		t.Fatal("could not find syncEndpointSlices in endpoint_slice.go — " +
			"has it been renamed or moved? This test's target must be updated alongside that change.")
	}
	collectConfiguratorCalls(syncFn, found)

	ctrlFile, err := parser.ParseFile(fset, "controller.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing controller.go: %v", err)
	}
	replicaFn := findFuncDecl(ctrlFile, "updateNumberOfIngressControllerReplicas")
	if replicaFn == nil {
		t.Fatal("could not find updateNumberOfIngressControllerReplicas in controller.go — " +
			"has it been renamed or moved? This test's target must be updated alongside that change.")
	}
	collectConfiguratorCalls(replicaFn, found)

	unexpected, missing := diffConfiguratorCalls(found)

	if len(unexpected) > 0 {
		t.Errorf("found Configurator call(s) reachable from syncEndpointSlices that are not on "+
			"configuratorCallAllowlist: %v. Before adding to the allowlist, verify the new call marks "+
			"the batch dirty (Configurator.deferReload) on any error path that can follow a successful "+
			"partial write — see the invariant documented there and on configuratorCallAllowlist above.",
			unexpected)
	}
	if len(missing) > 0 {
		t.Errorf("configuratorCallAllowlist lists method(s) no longer found reachable from "+
			"syncEndpointSlices: %v. The call was likely removed or renamed — update the allowlist to "+
			"match so it doesn't claim a wider reachable set than actually exists.", missing)
	}
}
