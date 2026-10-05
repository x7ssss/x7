package engine

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildFinalizerRemovalPatch(t *testing.T) {
	patchBytes := BuildFinalizerRemovalPatch()
	expected := `[{"op": "remove", "path": "/metadata/finalizers"}]`
	if string(patchBytes) != expected {
		t.Fatalf("unexpected patch bytes: got %s, want %s", string(patchBytes), expected)
	}

	var patchOps []map[string]interface{}
	if err := json.Unmarshal(patchBytes, &patchOps); err != nil {
		t.Fatalf("failed to unmarshal patch as valid RFC 6902 JSONPatch: %v", err)
	}

	if len(patchOps) != 1 {
		t.Fatalf("expected 1 patch operation, got %d", len(patchOps))
	}
	if patchOps[0]["op"] != "remove" || patchOps[0]["path"] != "/metadata/finalizers" {
		t.Fatalf("unexpected patch op contents: %+v", patchOps[0])
	}
}

func TestFinalizerPatcher_SafetyViolationOnNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	fakeDyn := fakedynamic.NewSimpleDynamicClient(scheme)
	patcher := NewFinalizerPatcher(fakeDyn)

	// Attempting to strip finalizers on a Namespace resource
	nsItem := ResourceAnalysis{
		GVR:        schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"},
		Name:       "stuck-namespace",
		Namespace:  "",
		Kind:       "Namespace",
		Finalizers: []string{"kubernetes"},
	}

	_, err := patcher.StripFinalizers(context.Background(), nsItem, false)
	if !errors.Is(err, ErrNamespaceFinalizerStrippingForbidden) {
		t.Fatalf("expected ErrNamespaceFinalizerStrippingForbidden, got %v", err)
	}
}

func TestFinalizerPatcher_ServerSideDryRunAndLivePatch(t *testing.T) {
	ctx := context.Background()

	gvr := schema.GroupVersionResource{
		Group:    "apps",
		Version:  "v1",
		Resource: "daemonsets",
	}

	dsObj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "DaemonSet",
			"metadata": map[string]interface{}{
				"name":      "stuck-ds",
				"namespace": "target-ns",
				"finalizers": []interface{}{
					"custom.operator/finalizer",
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	fakeDyn := fakedynamic.NewSimpleDynamicClient(scheme, dsObj)

	// Server-Side Dry-Run simulation:
	// In StripFinalizers with dryRun=false, call 1 is dry-run validation (non-mutating),
	// and call 2 is live patch execution (mutating).
	patchCalls := 0
	fakeDyn.PrependReactor("patch", "daemonsets", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		patchCalls++
		if patchCalls%2 == 1 {
			// Dry-run call: validate JSON syntax and return copy without mutating store
			patchAction := action.(clienttesting.PatchAction)
			var patchOps []map[string]interface{}
			if err := json.Unmarshal(patchAction.GetPatch(), &patchOps); err != nil {
				return true, nil, err
			}
			return true, dsObj.DeepCopy(), nil
		}
		// Live patch call: let fake dynamic client apply mutation to store
		return false, nil, nil
	})

	patcher := NewFinalizerPatcher(fakeDyn)

	item := ResourceAnalysis{
		GVR:        gvr,
		Name:       "stuck-ds",
		Namespace:  "target-ns",
		Kind:       "DaemonSet",
		Finalizers: []string{"custom.operator/finalizer"},
	}

	// 1. Dry-Run test: dryRun = true
	dryRes, err := patcher.StripFinalizers(ctx, item, true)
	if err != nil {
		t.Fatalf("StripFinalizers dry-run failed: %v", err)
	}
	if !dryRes.DryRun || !dryRes.Success {
		t.Fatalf("expected successful dry run result, got %+v", dryRes)
	}

	// Verify object still has finalizer after dry-run
	unchanged, err := fakeDyn.Resource(gvr).Namespace("target-ns").Get(ctx, "stuck-ds", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to fetch object after dry run: %v", err)
	}
	if len(unchanged.GetFinalizers()) != 1 {
		t.Fatalf("dry run mutated object unexpectedly: finalizers = %v", unchanged.GetFinalizers())
	}

	// 2. Live Patch test: dryRun = false
	liveRes, err := patcher.StripFinalizers(ctx, item, false)
	if err != nil {
		t.Fatalf("StripFinalizers live patch failed: %v", err)
	}
	if liveRes.DryRun || !liveRes.Success {
		t.Fatalf("expected successful live patch result, got %+v", liveRes)
	}

	// Verify object finalizers are now stripped
	updated, err := fakeDyn.Resource(gvr).Namespace("target-ns").Get(ctx, "stuck-ds", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to fetch object after live patch: %v", err)
	}
	if len(updated.GetFinalizers()) != 0 {
		t.Fatalf("expected finalizers to be empty, got %v", updated.GetFinalizers())
	}
}
