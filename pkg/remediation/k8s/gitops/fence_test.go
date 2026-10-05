package gitops

import (
	"context"
	"encoding/json"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	fakedynamic "k8s.io/client-go/dynamic/fake"
)

func TestBuildGitOpsPatches(t *testing.T) {
	// Test ArgoCD sync policy patch
	argoPatch := BuildArgoCDSyncPolicyPatch()
	var argoParsed map[string]interface{}
	if err := json.Unmarshal(argoPatch, &argoParsed); err != nil {
		t.Fatalf("failed to parse ArgoCD patch JSON: %v", err)
	}

	spec, ok := argoParsed["spec"].(map[string]interface{})
	if !ok {
		t.Fatalf("spec field missing in ArgoCD patch: %+v", argoParsed)
	}
	if val, exists := spec["syncPolicy"]; !exists || val != nil {
		t.Fatalf("expected syncPolicy to be null in patch, got %v", val)
	}

	// Test Flux suspend patch
	fluxPatch := BuildFluxSuspendPatch()
	var fluxParsed map[string]interface{}
	if err := json.Unmarshal(fluxPatch, &fluxParsed); err != nil {
		t.Fatalf("failed to parse Flux patch JSON: %v", err)
	}
	fluxSpec, ok := fluxParsed["spec"].(map[string]interface{})
	if !ok {
		t.Fatalf("spec field missing in Flux patch: %+v", fluxParsed)
	}
	if suspend, ok := fluxSpec["suspend"].(bool); !ok || !suspend {
		t.Fatalf("expected suspend to be true in Flux patch, got %v", fluxSpec["suspend"])
	}
}

func TestDiagnoseGitOps(t *testing.T) {
	ctx := context.Background()

	nsLabels := map[string]string{
		"argocd.argoproj.io/instance": "prod-stack",
	}

	item1 := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "api-server",
				"labels": map[string]interface{}{
					"kustomize.toolkit.fluxcd.io/name":      "infra-apps",
					"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
				},
			},
		},
	}

	item2 := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name": "api-svc",
				"labels": map[string]interface{}{
					"helm.toolkit.fluxcd.io/name": "redis-operator",
				},
			},
		},
	}

	candidates, err := DiagnoseGitOps(ctx, nil, "test-ns", nsLabels, []unstructured.Unstructured{item1, item2})
	if err != nil {
		t.Fatalf("DiagnoseGitOps failed: %v", err)
	}

	if len(candidates) != 3 {
		t.Fatalf("expected 3 candidates (Argo, Flux Kustomization, Flux HelmRelease), got %d", len(candidates))
	}

	foundArgo := false
	foundKust := false
	foundHelm := false

	for _, c := range candidates {
		switch c.Type {
		case ReconcilerArgoCD:
			if c.Name == "prod-stack" {
				foundArgo = true
			}
		case ReconcilerFluxKustomization:
			if c.Name == "infra-apps" && c.Namespace == "flux-system" {
				foundKust = true
			}
		case ReconcilerFluxHelmRelease:
			if c.Name == "redis-operator" && c.Namespace == "flux-system" {
				foundHelm = true
			}
		}
	}

	if !foundArgo {
		t.Errorf("expected Argo candidate prod-stack")
	}
	if !foundKust {
		t.Errorf("expected Flux Kustomization candidate infra-apps")
	}
	if !foundHelm {
		t.Errorf("expected Flux Helm candidate redis-operator")
	}
}

func TestFenceNamespaceGitOps(t *testing.T) {
	ctx := context.Background()

	argoApp := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "argoproj.io/v1alpha1",
			"kind":       "Application",
			"metadata": map[string]interface{}{
				"name":      "sample-app",
				"namespace": "argocd",
			},
			"spec": map[string]interface{}{
				"syncPolicy": map[string]interface{}{
					"automated": map[string]interface{}{},
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	fakeDyn := fakedynamic.NewSimpleDynamicClient(scheme, argoApp)

	candidate := GitOpsCandidate{
		Type:         ReconcilerArgoCD,
		Name:         "sample-app",
		Namespace:    "argocd",
		PatchPayload: string(BuildArgoCDSyncPolicyPatch()),
	}

	// 1. Dry run
	dryResults, err := FenceNamespaceGitOps(ctx, fakeDyn, []GitOpsCandidate{candidate}, true)
	if err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	if len(dryResults) != 1 || !dryResults[0].DryRun || !dryResults[0].Success {
		t.Fatalf("unexpected dry run result: %+v", dryResults)
	}

	// 2. Live run
	liveResults, err := FenceNamespaceGitOps(ctx, fakeDyn, []GitOpsCandidate{candidate}, false)
	if err != nil {
		t.Fatalf("live run failed: %v", err)
	}
	if len(liveResults) != 1 || liveResults[0].DryRun || !liveResults[0].Success {
		t.Fatalf("unexpected live result: %+v", liveResults)
	}
}
