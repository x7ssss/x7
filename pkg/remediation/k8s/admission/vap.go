package admission

import (
	"context"
	"fmt"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// VAPBindingCandidate represents a ValidatingAdmissionPolicyBinding referencing parameters in the terminating namespace with Deny action.
type VAPBindingCandidate struct {
	BindingName                    string `json:"bindingName"`
	PolicyName                     string `json:"policyName"`
	ParamRefNamespace              string `json:"paramRefNamespace"`
	ParamRefName                   string `json:"paramRefName,omitempty"`
	CurrentParameterNotFoundAction string `json:"currentParameterNotFoundAction"`
	PatchPayload                   string `json:"patchPayload"`
}

// VAPRemediationResult represents the result of disarming a VAP binding.
type VAPRemediationResult struct {
	BindingName string `json:"bindingName"`
	Action      string `json:"action"`
	DryRun      bool   `json:"dryRun"`
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	Error       string `json:"error,omitempty"`
}

// BuildVAPParameterDisarmPatch returns an RFC 7386 JSON Merge Patch payload to set parameterNotFoundAction to Allow.
func BuildVAPParameterDisarmPatch() []byte {
	return []byte(`{"spec":{"paramRef":{"parameterNotFoundAction":"Allow"}}}`)
}

// DiagnoseVAP inspects cluster ValidatingAdmissionPolicyBinding resources for dependencies on the target namespace.
func DiagnoseVAP(ctx context.Context, client kubernetes.Interface, targetNamespace string) ([]VAPBindingCandidate, error) {
	var candidates []VAPBindingCandidate

	bindingList, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) || strings.Contains(err.Error(), "the server could not find the requested resource") {
			// Cluster does not have ValidatingAdmissionPolicy feature enabled (< 1.28 or disabled)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list ValidatingAdmissionPolicyBindings: %w", err)
	}

	for _, binding := range bindingList.Items {
		if binding.Spec.ParamRef != nil && strings.EqualFold(binding.Spec.ParamRef.Namespace, targetNamespace) {
			currentAction := "Deny" // Default action in K8s VAP is Deny
			if binding.Spec.ParamRef.ParameterNotFoundAction != nil {
				currentAction = string(*binding.Spec.ParamRef.ParameterNotFoundAction)
			}

			if currentAction == string(admissionregistrationv1.DenyAction) {
				candidates = append(candidates, VAPBindingCandidate{
					BindingName:                    binding.Name,
					PolicyName:                     binding.Spec.PolicyName,
					ParamRefNamespace:              binding.Spec.ParamRef.Namespace,
					ParamRefName:                   binding.Spec.ParamRef.Name,
					CurrentParameterNotFoundAction: currentAction,
					PatchPayload:                   string(BuildVAPParameterDisarmPatch()),
				})
			}
		}
	}

	return candidates, nil
}

// DisarmVAPBindings patches the candidate bindings so parameterNotFoundAction becomes Allow, preventing DELETE blocks.
func DisarmVAPBindings(ctx context.Context, client kubernetes.Interface, candidates []VAPBindingCandidate, dryRun bool) ([]VAPRemediationResult, error) {
	var results []VAPRemediationResult

	for _, c := range candidates {
		patchData := []byte(c.PatchPayload)

		if dryRun {
			results = append(results, VAPRemediationResult{
				BindingName: c.BindingName,
				Action:      "DISARM_VAP_PARAMETER_NOT_FOUND",
				DryRun:      true,
				Success:     true,
				Message: fmt.Sprintf("Plan to patch parameterNotFoundAction to Allow on ValidatingAdmissionPolicyBinding %s (policy: %s, paramRef: %s/%s)",
					c.BindingName, c.PolicyName, c.ParamRefNamespace, c.ParamRefName),
			})
			continue
		}

		_, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Patch(
			ctx, c.BindingName, types.MergePatchType, patchData, metav1.PatchOptions{})
		if err != nil {
			results = append(results, VAPRemediationResult{
				BindingName: c.BindingName,
				Action:      "DISARM_VAP_PARAMETER_NOT_FOUND",
				DryRun:      false,
				Success:     false,
				Message:     fmt.Sprintf("Failed to disarm VAP binding %s", c.BindingName),
				Error:       err.Error(),
			})
		} else {
			results = append(results, VAPRemediationResult{
				BindingName: c.BindingName,
				Action:      "DISARM_VAP_PARAMETER_NOT_FOUND",
				DryRun:      false,
				Success:     true,
				Message: fmt.Sprintf("Successfully patched parameterNotFoundAction=Allow on ValidatingAdmissionPolicyBinding %s",
					c.BindingName),
			})
		}
	}

	return results, nil
}
