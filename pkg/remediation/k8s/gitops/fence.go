package gitops

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

type GitOpsReconcilerType string

const (
	ReconcilerArgoCD            GitOpsReconcilerType = "ArgoCD"
	ReconcilerFluxKustomization GitOpsReconcilerType = "FluxKustomization"
	ReconcilerFluxHelmRelease   GitOpsReconcilerType = "FluxHelmRelease"

	DefaultArgoCDNamespace = "argocd"
	DefaultFluxNamespace   = "flux-system"
)

var (
	ArgoCDApplicationGVR = schema.GroupVersionResource{
		Group:    "argoproj.io",
		Version:  "v1alpha1",
		Resource: "applications",
	}
	FluxKustomizationGVR = schema.GroupVersionResource{
		Group:    "kustomize.toolkit.fluxcd.io",
		Version:  "v1",
		Resource: "kustomizations",
	}
	FluxHelmReleaseGVR = schema.GroupVersionResource{
		Group:    "helm.toolkit.fluxcd.io",
		Version:  "v2",
		Resource: "helmreleases",
	}
)

// GitOpsCandidate represents a GitOps reconciler discovered via tracking labels or spec destinations.
type GitOpsCandidate struct {
	Type         GitOpsReconcilerType `json:"type"`
	Name         string               `json:"name"`
	Namespace    string               `json:"namespace"`
	SourceLabel  string               `json:"sourceLabel,omitempty"`
	Action       string               `json:"action"`
	PatchPayload string               `json:"patchPayload"`
}

// GitOpsFenceResult represents the outcome of fencing a GitOps reconciler.
type GitOpsFenceResult struct {
	Candidate GitOpsCandidate `json:"candidate"`
	DryRun    bool            `json:"dryRun"`
	Success   bool            `json:"success"`
	Message   string          `json:"message"`
	Error     string          `json:"error,omitempty"`
}

// BuildArgoCDSyncPolicyPatch returns an RFC 7386 JSON Merge Patch payload to remove syncPolicy (set to null).
func BuildArgoCDSyncPolicyPatch() []byte {
	return []byte(`{"spec":{"syncPolicy":null}}`)
}

// BuildFluxSuspendPatch returns an RFC 7386 JSON Merge Patch payload to suspend Flux reconciliation.
func BuildFluxSuspendPatch() []byte {
	return []byte(`{"spec":{"suspend":true}}`)
}

// DiagnoseGitOps inspects namespace labels, annotations, and child object tracking labels for ArgoCD and Flux reconcilers.
func DiagnoseGitOps(
	ctx context.Context,
	dynClient dynamic.Interface,
	targetNamespace string,
	nsLabels map[string]string,
	items []unstructured.Unstructured,
) ([]GitOpsCandidate, error) {
	var candidates []GitOpsCandidate
	seen := make(map[string]bool)

	addCandidate := func(c GitOpsCandidate) {
		key := fmt.Sprintf("%s/%s/%s", c.Type, c.Namespace, c.Name)
		if !seen[key] {
			seen[key] = true
			candidates = append(candidates, c)
		}
	}

	inspectLabels := func(labels map[string]string) {
		if labels == nil {
			return
		}

		// 1. ArgoCD tracking labels
		if appName, ok := labels["argocd.argoproj.io/instance"]; ok && appName != "" {
			addCandidate(GitOpsCandidate{
				Type:         ReconcilerArgoCD,
				Name:         appName,
				Namespace:    DefaultArgoCDNamespace,
				SourceLabel:  "argocd.argoproj.io/instance",
				Action:       "CLEAR_SYNC_POLICY",
				PatchPayload: string(BuildArgoCDSyncPolicyPatch()),
			})
		}
		if trackingID, ok := labels["argocd.argoproj.io/tracking-id"]; ok && trackingID != "" {
			parts := strings.Split(trackingID, ":")
			if len(parts) > 0 && parts[0] != "" {
				appName := parts[0]
				addCandidate(GitOpsCandidate{
					Type:         ReconcilerArgoCD,
					Name:         appName,
					Namespace:    DefaultArgoCDNamespace,
					SourceLabel:  "argocd.argoproj.io/tracking-id",
					Action:       "CLEAR_SYNC_POLICY",
					PatchPayload: string(BuildArgoCDSyncPolicyPatch()),
				})
			}
		}

		// 2. Flux Kustomization tracking labels
		if kustName, ok := labels["kustomize.toolkit.fluxcd.io/name"]; ok && kustName != "" {
			kustNS := labels["kustomize.toolkit.fluxcd.io/namespace"]
			if kustNS == "" {
				kustNS = DefaultFluxNamespace
			}
			addCandidate(GitOpsCandidate{
				Type:         ReconcilerFluxKustomization,
				Name:         kustName,
				Namespace:    kustNS,
				SourceLabel:  "kustomize.toolkit.fluxcd.io/name",
				Action:       "SUSPEND_KUSTOMIZATION",
				PatchPayload: string(BuildFluxSuspendPatch()),
			})
		}

		// 3. Flux HelmRelease tracking labels
		if helmName, ok := labels["helm.toolkit.fluxcd.io/name"]; ok && helmName != "" {
			helmNS := labels["helm.toolkit.fluxcd.io/namespace"]
			if helmNS == "" {
				helmNS = DefaultFluxNamespace
			}
			addCandidate(GitOpsCandidate{
				Type:         ReconcilerFluxHelmRelease,
				Name:         helmName,
				Namespace:    helmNS,
				SourceLabel:  "helm.toolkit.fluxcd.io/name",
				Action:       "SUSPEND_HELM_RELEASE",
				PatchPayload: string(BuildFluxSuspendPatch()),
			})
		}
	}

	// Check namespace labels
	inspectLabels(nsLabels)

	// Check child items labels
	for _, item := range items {
		inspectLabels(item.GetLabels())
	}

	// Also inspect ArgoCD Application CRs directly if CRD exists in cluster
	if dynClient != nil {
		appClient := dynClient.Resource(ArgoCDApplicationGVR).Namespace(DefaultArgoCDNamespace)
		if appList, err := appClient.List(ctx, metav1.ListOptions{}); err == nil {
			for _, app := range appList.Items {
				destNS, _, _ := unstructured.NestedString(app.Object, "spec", "destination", "namespace")
				if strings.EqualFold(destNS, targetNamespace) {
					addCandidate(GitOpsCandidate{
						Type:         ReconcilerArgoCD,
						Name:         app.GetName(),
						Namespace:    DefaultArgoCDNamespace,
						SourceLabel:  "spec.destination.namespace",
						Action:       "CLEAR_SYNC_POLICY",
						PatchPayload: string(BuildArgoCDSyncPolicyPatch()),
					})
				}
			}
		}
	}

	return candidates, nil
}

// FenceNamespaceGitOps applies patches to disable self-healing and suspend GitOps reconcilers.
func FenceNamespaceGitOps(
	ctx context.Context,
	dynClient dynamic.Interface,
	candidates []GitOpsCandidate,
	dryRun bool,
) ([]GitOpsFenceResult, error) {
	var results []GitOpsFenceResult

	for _, c := range candidates {
		patchData := []byte(c.PatchPayload)

		if dryRun {
			results = append(results, GitOpsFenceResult{
				Candidate: c,
				DryRun:    true,
				Success:   true,
				Message: fmt.Sprintf("Plan to fence %s reconciler %s/%s (payload: %s)",
					c.Type, c.Namespace, c.Name, c.PatchPayload),
			})
			continue
		}

		var gvr schema.GroupVersionResource
		switch c.Type {
		case ReconcilerArgoCD:
			gvr = ArgoCDApplicationGVR
		case ReconcilerFluxKustomization:
			gvr = FluxKustomizationGVR
		case ReconcilerFluxHelmRelease:
			gvr = FluxHelmReleaseGVR
		default:
			continue
		}

		_, err := dynClient.Resource(gvr).Namespace(c.Namespace).Patch(
			ctx, c.Name, types.MergePatchType, patchData, metav1.PatchOptions{})
		if err != nil {
			results = append(results, GitOpsFenceResult{
				Candidate: c,
				DryRun:    false,
				Success:   false,
				Message:   fmt.Sprintf("Failed to fence %s %s/%s", c.Type, c.Namespace, c.Name),
				Error:     err.Error(),
			})
		} else {
			results = append(results, GitOpsFenceResult{
				Candidate: c,
				DryRun:    false,
				Success:   true,
				Message: fmt.Sprintf("Successfully fenced %s reconciler %s/%s to prevent automatic re-creation",
					c.Type, c.Namespace, c.Name),
			})
		}
	}

	return results, nil
}
