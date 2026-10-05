package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

// ErrNamespaceFinalizerStrippingForbidden is returned when an attempt is made to strip finalizers from a Namespace.
var ErrNamespaceFinalizerStrippingForbidden = errors.New(
	"safety violation: refusing to strip finalizers from Namespace resource to prevent etcd corruption and ghost object leaks",
)

// BuildFinalizerRemovalPatch constructs the RFC 6902 JSONPatch to remove finalizers.
func BuildFinalizerRemovalPatch() []byte {
	return []byte(`[{"op": "remove", "path": "/metadata/finalizers"}]`)
}

// FinalizerPatcher safely strips finalizers from deadlocked child objects using server-side dry-run validation.
type FinalizerPatcher struct {
	dynamicClient dynamic.Interface
}

// NewFinalizerPatcher creates a new FinalizerPatcher.
func NewFinalizerPatcher(dynamicClient dynamic.Interface) *FinalizerPatcher {
	return &FinalizerPatcher{dynamicClient: dynamicClient}
}

// StripFinalizers validates via server-side dry-run and then applies live RFC 6902 JSONPatch to remove finalizers.
func (p *FinalizerPatcher) StripFinalizers(ctx context.Context, item ResourceAnalysis, dryRun bool) (*PatchResult, error) {
	// STRICT SAFETY CHECK: NEVER strip finalizers from Namespace resources!
	if item.GVR.Resource == "namespaces" || strings.EqualFold(item.Kind, "Namespace") {
		return nil, ErrNamespaceFinalizerStrippingForbidden
	}

	if len(item.Finalizers) == 0 {
		return &PatchResult{
			GVR:       item.GVR,
			Namespace: item.Namespace,
			Name:      item.Name,
			DryRun:    dryRun,
			Success:   true,
			Message:   "No finalizers present; skipped",
		}, nil
	}

	patchBytes := BuildFinalizerRemovalPatch()

	// Step 1: Server-Side Dry-Run validation (metav1.DryRunAll)
	dryRunOpts := metav1.PatchOptions{
		DryRun: []string{metav1.DryRunAll},
	}

	_, err := p.dynamicClient.Resource(item.GVR).Namespace(item.Namespace).Patch(
		ctx, item.Name, types.JSONPatchType, patchBytes, dryRunOpts)
	if err != nil {
		return &PatchResult{
			GVR:       item.GVR,
			Namespace: item.Namespace,
			Name:      item.Name,
			DryRun:    true,
			Success:   false,
			Message:   "Server-side dry-run validation failed",
			Error:     err.Error(),
		}, fmt.Errorf("server-side dry-run failed for %s/%s (%s): %w", item.Namespace, item.Name, item.GVR.Resource, err)
	}

	// If in dry-run mode, we return the successful dry-run validation result
	if dryRun {
		return &PatchResult{
			GVR:       item.GVR,
			Namespace: item.Namespace,
			Name:      item.Name,
			DryRun:    true,
			Success:   true,
			Message: fmt.Sprintf("Server-side dry-run succeeded (200 OK) for RFC 6902 finalizer removal on %s/%s",
				item.Namespace, item.Name),
		}, nil
	}

	// Step 2: Live Patch application
	liveOpts := metav1.PatchOptions{}
	_, err = p.dynamicClient.Resource(item.GVR).Namespace(item.Namespace).Patch(
		ctx, item.Name, types.JSONPatchType, patchBytes, liveOpts)
	if err != nil {
		return &PatchResult{
			GVR:       item.GVR,
			Namespace: item.Namespace,
			Name:      item.Name,
			DryRun:    false,
			Success:   false,
			Message:   "Live finalizer strip patch failed",
			Error:     err.Error(),
		}, fmt.Errorf("live patch failed for %s/%s (%s): %w", item.Namespace, item.Name, item.GVR.Resource, err)
	}

	return &PatchResult{
		GVR:       item.GVR,
		Namespace: item.Namespace,
		Name:      item.Name,
		DryRun:    false,
		Success:   true,
		Message: fmt.Sprintf("Successfully stripped finalizers from %s/%s (%s)",
			item.Namespace, item.Name, item.GVR.Resource),
	}, nil
}
