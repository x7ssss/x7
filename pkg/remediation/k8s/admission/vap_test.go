package admission

import (
	"context"
	"encoding/json"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestBuildVAPParameterDisarmPatch(t *testing.T) {
	patch := BuildVAPParameterDisarmPatch()
	var parsed map[string]interface{}
	if err := json.Unmarshal(patch, &parsed); err != nil {
		t.Fatalf("failed to unmarshal VAP disarm patch JSON: %v", err)
	}

	spec, ok := parsed["spec"].(map[string]interface{})
	if !ok {
		t.Fatalf("spec field missing in patch: %+v", parsed)
	}
	paramRef, ok := spec["paramRef"].(map[string]interface{})
	if !ok {
		t.Fatalf("paramRef field missing in patch: %+v", spec)
	}
	if action, ok := paramRef["parameterNotFoundAction"].(string); !ok || action != "Allow" {
		t.Fatalf("expected parameterNotFoundAction to be Allow, got %v", paramRef["parameterNotFoundAction"])
	}
}

func TestDiagnoseAndDisarmVAP(t *testing.T) {
	ctx := context.Background()

	denyAction := admissionregistrationv1.DenyAction
	allowAction := admissionregistrationv1.AllowAction

	// 1. Binding referencing terminating namespace with explicit Deny
	binding1 := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-binding-deny",
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "check-network-policy",
			ParamRef: &admissionregistrationv1.ParamRef{
				Namespace:               "target-ns",
				Name:                    "config-param",
				ParameterNotFoundAction: &denyAction,
			},
		},
	}

	// 2. Binding referencing terminating namespace with default nil (Deny)
	binding2 := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-binding-default-deny",
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "check-labels",
			ParamRef: &admissionregistrationv1.ParamRef{
				Namespace: "target-ns",
				Name:      "label-param",
			},
		},
	}

	// 3. Binding referencing terminating namespace with Allow (already safe)
	binding3 := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-binding-already-allowed",
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "check-quota",
			ParamRef: &admissionregistrationv1.ParamRef{
				Namespace:               "target-ns",
				Name:                    "quota-param",
				ParameterNotFoundAction: &allowAction,
			},
		},
	}

	// 4. Binding referencing other namespace
	binding4 := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-binding-other-ns",
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: "check-storage",
			ParamRef: &admissionregistrationv1.ParamRef{
				Namespace:               "other-ns",
				Name:                    "storage-param",
				ParameterNotFoundAction: &denyAction,
			},
		},
	}

	client := fake.NewSimpleClientset(binding1, binding2, binding3, binding4)

	// Diagnose
	candidates, err := DiagnoseVAP(ctx, client, "target-ns")
	if err != nil {
		t.Fatalf("DiagnoseVAP failed: %v", err)
	}

	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates needing disarming, got %d", len(candidates))
	}

	// Remediate dry-run
	dryResults, err := DisarmVAPBindings(ctx, client, candidates, true)
	if err != nil {
		t.Fatalf("DisarmVAPBindings dry-run failed: %v", err)
	}
	if len(dryResults) != 2 || !dryResults[0].DryRun || !dryResults[0].Success {
		t.Fatalf("unexpected dry-run results: %+v", dryResults)
	}

	// Remediate live
	liveResults, err := DisarmVAPBindings(ctx, client, candidates, false)
	if err != nil {
		t.Fatalf("DisarmVAPBindings live failed: %v", err)
	}
	if len(liveResults) != 2 || liveResults[0].DryRun || !liveResults[0].Success {
		t.Fatalf("unexpected live results: %+v", liveResults)
	}
}
