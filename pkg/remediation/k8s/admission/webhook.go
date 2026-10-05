package admission

import (
	"context"
	"fmt"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

type WebhookKind string

const (
	MutatingWebhookKind   WebhookKind = "MutatingWebhookConfiguration"
	ValidatingWebhookKind WebhookKind = "ValidatingWebhookConfiguration"
)

// WebhookCandidate represents an admission webhook located inside the terminating namespace with Fail policy.
type WebhookCandidate struct {
	ConfigName           string      `json:"configName"`
	Kind                 WebhookKind `json:"kind"`
	WebhookIndex         int         `json:"webhookIndex"`
	WebhookName          string      `json:"webhookName"`
	ServiceNamespace     string      `json:"serviceNamespace"`
	ServiceName          string      `json:"serviceName"`
	CurrentFailurePolicy string      `json:"currentFailurePolicy"`
	PatchJSON            string      `json:"patchJSON"`
}

// WebhookRemediationResult represents the result of neutralizing a webhook.
type WebhookRemediationResult struct {
	ConfigName   string      `json:"configName"`
	Kind         WebhookKind `json:"kind"`
	WebhookIndex int         `json:"webhookIndex"`
	WebhookName  string      `json:"webhookName"`
	Action       string      `json:"action"`
	DryRun       bool        `json:"dryRun"`
	Success      bool        `json:"success"`
	Message      string      `json:"message"`
	Error        string      `json:"error,omitempty"`
}

// WebhookNeutralizer neutralizes webhooks hosted in a terminating namespace that block namespace teardown.
type WebhookNeutralizer struct {
	client kubernetes.Interface
}

// NewWebhookNeutralizer creates a new WebhookNeutralizer.
func NewWebhookNeutralizer(client kubernetes.Interface) *WebhookNeutralizer {
	return &WebhookNeutralizer{client: client}
}

// BuildWebhookPatch constructs an RFC 6902 JSONPatch to set failurePolicy to Ignore.
func BuildWebhookPatch(index int) []byte {
	return []byte(fmt.Sprintf(`[{"op": "replace", "path": "/webhooks/%d/failurePolicy", "value": "Ignore"}]`, index))
}

// Diagnose inspects Mutating and Validating webhook configurations for webhooks backed by the target namespace.
func (n *WebhookNeutralizer) Diagnose(ctx context.Context, targetNamespace string) ([]WebhookCandidate, error) {
	var candidates []WebhookCandidate

	// 1. Inspect MutatingWebhookConfigurations
	mutatingList, err := n.client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list mutating webhook configurations: %w", err)
	}

	for _, cfg := range mutatingList.Items {
		for idx, wh := range cfg.Webhooks {
			if wh.ClientConfig.Service != nil && strings.EqualFold(wh.ClientConfig.Service.Namespace, targetNamespace) {
				currentPolicy := "Fail"
				if wh.FailurePolicy != nil {
					currentPolicy = string(*wh.FailurePolicy)
				}

				if currentPolicy == string(admissionregistrationv1.Fail) {
					candidates = append(candidates, WebhookCandidate{
						ConfigName:           cfg.Name,
						Kind:                 MutatingWebhookKind,
						WebhookIndex:         idx,
						WebhookName:          wh.Name,
						ServiceNamespace:     wh.ClientConfig.Service.Namespace,
						ServiceName:          wh.ClientConfig.Service.Name,
						CurrentFailurePolicy: currentPolicy,
						PatchJSON:            string(BuildWebhookPatch(idx)),
					})
				}
			}
		}
	}

	// 2. Inspect ValidatingWebhookConfigurations
	validatingList, err := n.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list validating webhook configurations: %w", err)
	}

	for _, cfg := range validatingList.Items {
		for idx, wh := range cfg.Webhooks {
			if wh.ClientConfig.Service != nil && strings.EqualFold(wh.ClientConfig.Service.Namespace, targetNamespace) {
				currentPolicy := "Fail"
				if wh.FailurePolicy != nil {
					currentPolicy = string(*wh.FailurePolicy)
				}

				if currentPolicy == string(admissionregistrationv1.Fail) {
					candidates = append(candidates, WebhookCandidate{
						ConfigName:           cfg.Name,
						Kind:                 ValidatingWebhookKind,
						WebhookIndex:         idx,
						WebhookName:          wh.Name,
						ServiceNamespace:     wh.ClientConfig.Service.Namespace,
						ServiceName:          wh.ClientConfig.Service.Name,
						CurrentFailurePolicy: currentPolicy,
						PatchJSON:            string(BuildWebhookPatch(idx)),
					})
				}
			}
		}
	}

	return candidates, nil
}

// Remediate patches the identified webhooks to set failurePolicy to Ignore.
func (n *WebhookNeutralizer) Remediate(ctx context.Context, candidates []WebhookCandidate, dryRun bool) ([]WebhookRemediationResult, error) {
	var results []WebhookRemediationResult

	for _, candidate := range candidates {
		patchData := []byte(candidate.PatchJSON)

		if dryRun {
			results = append(results, WebhookRemediationResult{
				ConfigName:   candidate.ConfigName,
				Kind:         candidate.Kind,
				WebhookIndex: candidate.WebhookIndex,
				WebhookName:  candidate.WebhookName,
				Action:       "PATCH_FAILURE_POLICY_IGNORE",
				DryRun:       true,
				Success:      true,
				Message: fmt.Sprintf("Plan to patch failurePolicy to Ignore on %s %s (webhook: %s, index: %d)",
					candidate.Kind, candidate.ConfigName, candidate.WebhookName, candidate.WebhookIndex),
			})
			continue
		}

		// Live execution: apply RFC 6902 JSONPatch
		var err error
		if candidate.Kind == MutatingWebhookKind {
			_, err = n.client.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(
				ctx, candidate.ConfigName, types.JSONPatchType, patchData, metav1.PatchOptions{})
		} else {
			_, err = n.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Patch(
				ctx, candidate.ConfigName, types.JSONPatchType, patchData, metav1.PatchOptions{})
		}

		if err != nil {
			results = append(results, WebhookRemediationResult{
				ConfigName:   candidate.ConfigName,
				Kind:         candidate.Kind,
				WebhookIndex: candidate.WebhookIndex,
				WebhookName:  candidate.WebhookName,
				Action:       "PATCH_FAILURE_POLICY_IGNORE",
				DryRun:       false,
				Success:      false,
				Message: fmt.Sprintf("Failed to patch %s %s", candidate.Kind, candidate.ConfigName),
				Error:   err.Error(),
			})
		} else {
			results = append(results, WebhookRemediationResult{
				ConfigName:   candidate.ConfigName,
				Kind:         candidate.Kind,
				WebhookIndex: candidate.WebhookIndex,
				WebhookName:  candidate.WebhookName,
				Action:       "PATCH_FAILURE_POLICY_IGNORE",
				DryRun:       false,
				Success:      true,
				Message: fmt.Sprintf("Successfully neutralized webhook failurePolicy to Ignore on %s %s (webhook: %s)",
					candidate.Kind, candidate.ConfigName, candidate.WebhookName),
			})
		}
	}

	return results, nil
}
