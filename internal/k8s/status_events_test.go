package k8s

import (
	"context"
	"errors"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
)

// newEventTestLBC returns a controller that records events but skips status updates.
func newEventTestLBC() (*LoadBalancerController, *record.FakeRecorder) {
	recorder := record.NewFakeRecorder(10)
	return &LoadBalancerController{
		recorder: recorder,
		Logger:   nl.LoggerFromContext(context.Background()),
		// Leader election on with no elector disables status reporting.
		isLeaderElectionEnabled: true,
	}, recorder
}

func TestMinionEventMessages(t *testing.T) {
	t.Parallel()

	errApply := errors.New("reload failed")

	tests := []struct {
		name          string
		childWarnings []string
		warnings      []string
		err           error
		want          string
	}{
		{
			name: "no warnings no error",
			want: "Normal AddedOrUpdated Configuration for default/minion was added or updated",
		},
		{
			name: "error only",
			err:  errApply,
			want: "Warning AddedOrUpdatedWithError Configuration for default/minion was added or updated but was not applied: reload failed",
		},
		{
			name:          "child warnings and error",
			childWarnings: []string{"w1"},
			err:           errApply,
			want:          "Warning AddedOrUpdatedWithError Configuration for default/minion was added or updated with warning(s): w1; but was not applied: reload failed",
		},
		{
			name:          "child warnings, config warnings and error",
			childWarnings: []string{"w1"},
			warnings:      []string{"w2"},
			err:           errApply,
			want:          "Warning AddedOrUpdatedWithError Configuration for default/minion was added or updated with warning(s): w1; with warning(s): w2; but was not applied: reload failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lbc, recorder := newEventTestLBC()
			master := &networking.Ingress{ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "master"}}
			minion := &networking.Ingress{ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "minion"}}
			ingConfig := &IngressConfiguration{
				Ingress:       master,
				IsMaster:      true,
				Minions:       []*MinionConfiguration{{Ingress: minion}},
				ChildWarnings: map[string][]string{},
			}
			if tc.childWarnings != nil {
				ingConfig.ChildWarnings["default/minion"] = tc.childWarnings
			}
			warnings := configs.Warnings{}
			if tc.warnings != nil {
				warnings[minion] = tc.warnings
			}

			lbc.updateMergeableIngressStatusAndEvents(ingConfig, warnings, tc.err)

			<-recorder.Events // master event
			if got := <-recorder.Events; got != tc.want {
				t.Errorf("minion event:\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

func TestVirtualServerRouteEventMessages(t *testing.T) {
	t.Parallel()

	errApply := errors.New("reload failed")

	tests := []struct {
		name     string
		warnings []string
		err      error
		want     string
	}{
		{
			name: "no warnings no error",
			want: "Normal AddedOrUpdated Configuration for default/vsr was added or updated",
		},
		{
			name:     "warnings only",
			warnings: []string{"w1"},
			want:     "Warning AddedOrUpdatedWithWarning Configuration for default/vsr was added or updated with warning(s): w1",
		},
		{
			name: "error only",
			err:  errApply,
			want: "Warning AddedOrUpdatedWithError Configuration for default/vsr was added or updated but was not applied: reload failed",
		},
		{
			name:     "warnings and error",
			warnings: []string{"w1"},
			err:      errApply,
			want:     "Warning AddedOrUpdatedWithError Configuration for default/vsr was added or updated with warning(s): w1; but was not applied: reload failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lbc, recorder := newEventTestLBC()
			vsr := &conf_v1.VirtualServerRoute{ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "vsr"}}
			vsConfig := &VirtualServerConfiguration{
				VirtualServer:       &conf_v1.VirtualServer{ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "vs"}},
				VirtualServerRoutes: []*conf_v1.VirtualServerRoute{vsr},
			}
			warnings := configs.Warnings{}
			if tc.warnings != nil {
				warnings[vsr] = tc.warnings
			}

			lbc.updateAttachedVirtualServerRoutesStatusAndEvents(vsConfig, warnings, tc.err)

			if got := <-recorder.Events; got != tc.want {
				t.Errorf("VSR event:\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestResourceEventMessages covers regular Ingress, VirtualServer and TransportServer events, which share one format.
func TestResourceEventMessages(t *testing.T) {
	t.Parallel()

	meta := meta_v1.ObjectMeta{Namespace: "default", Name: "res"}
	kinds := map[string]func(lbc *LoadBalancerController, configWarnings, warnings []string, err error){
		"Ingress": func(lbc *LoadBalancerController, configWarnings, warnings []string, err error) {
			ing := &networking.Ingress{ObjectMeta: meta}
			w := configs.Warnings{}
			if warnings != nil {
				w[ing] = warnings
			}
			lbc.updateRegularIngressStatusAndEvents(&IngressConfiguration{Ingress: ing, Warnings: configWarnings}, w, err)
		},
		"VirtualServer": func(lbc *LoadBalancerController, configWarnings, warnings []string, err error) {
			vs := &conf_v1.VirtualServer{ObjectMeta: meta}
			w := configs.Warnings{}
			if warnings != nil {
				w[vs] = warnings
			}
			lbc.updateVirtualServerOwnStatusAndEvents(&VirtualServerConfiguration{VirtualServer: vs, Warnings: configWarnings}, w, err, false)
		},
		"TransportServer": func(lbc *LoadBalancerController, configWarnings, warnings []string, err error) {
			ts := &conf_v1.TransportServer{ObjectMeta: meta}
			w := configs.Warnings{}
			if warnings != nil {
				w[ts] = warnings
			}
			lbc.updateTransportServerStatusAndEvents(&TransportServerConfiguration{TransportServer: ts, Warnings: configWarnings}, w, err)
		},
	}

	errApply := errors.New("reload failed")
	const prefix = "Configuration for default/res was added or updated"

	tests := []struct {
		name           string
		configWarnings []string
		warnings       []string
		err            error
		want           string
	}{
		{
			name: "no warnings no error",
			want: "Normal AddedOrUpdated " + prefix,
		},
		{
			name:           "config warnings only",
			configWarnings: []string{"w1"},
			want:           "Warning AddedOrUpdatedWithWarning " + prefix + " with warning(s): w1",
		},
		{
			name:     "generated warnings only",
			warnings: []string{"w2"},
			want:     "Warning AddedOrUpdatedWithWarning " + prefix + " with warning(s): w2",
		},
		{
			name: "error only",
			err:  errApply,
			want: "Warning AddedOrUpdatedWithError " + prefix + " but was not applied: reload failed",
		},
		{
			name:           "config warnings and error",
			configWarnings: []string{"w1"},
			err:            errApply,
			want:           "Warning AddedOrUpdatedWithError " + prefix + " with warning(s): w1; but was not applied: reload failed",
		},
	}

	for kind, update := range kinds {
		for _, tc := range tests {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				lbc, recorder := newEventTestLBC()
				update(lbc, tc.configWarnings, tc.warnings, tc.err)

				if got := <-recorder.Events; got != tc.want {
					t.Errorf("event:\n got: %q\nwant: %q", got, tc.want)
				}
			})
		}
	}
}
