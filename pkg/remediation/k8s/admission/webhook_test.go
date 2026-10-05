package admission

import (
	"context"
	"encoding/json"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestBuildWebhookPatch(t *testing.T) {
	patch := BuildWebhookPatch(2)
	expected := `[{"op": "replace", "path": "/webhooks/2/failurePolicy", "value": "Ignore"}]`
	if string(patch) != expected {
		t.Fatalf("unexpected patch JSON: got %s, want %s", string(patch), expected)
	}

	var parsed []map[string]interface{}
	if err := json.Unmarshal(patch, &parsed); err != nil {
		t.Fatalf("patch JSON is not valid RFC 6902 JSONPatch: %v", err)
	}
	if len(parsed) != 1 || parsed[0]["op"] != "replace" || parsed[0]["path"] != "/webhooks/2/failurePolicy" || parsed[0]["value"] != "Ignore" {
		t.Fatalf("parsed patch content mismatch: %+v", parsed)
	}
}

func TestWebhookNeutralizer_DiagnoseAndRemediate(t *testing.T) {
	ctx := context.Background()

	failPolicy := admissionregistrationv1.Fail
	ignorePolicy := admissionregistrationv1.Ignore

	mutatingCfg := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-mutator",
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name: "mutator.stuck.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: "terminating-ns",
						Name:      "mutator-svc",
					},
				},
				FailurePolicy: &failPolicy,
			},
			{
				Name: "external.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: "other-ns",
						Name:      "other-svc",
					},
				},
				FailurePolicy: &failPolicy,
			},
		},
	}

	validatingCfg := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-validator",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "validator.stuck.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: "terminating-ns",
						Name:      "validator-svc",
					},
				},
				FailurePolicy: &failPolicy,
			},
			{
				Name: "already-ignored.stuck.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: "terminating-ns",
						Name:      "validator-svc-2",
					},
				},
				FailurePolicy: &ignorePolicy,
			},
		},
	}

	client := fake.NewSimpleClientset(mutatingCfg, validatingCfg)
	neutralizer := NewWebhookNeutralizer(client)

	// Diagnose
	candidates, err := neutralizer.Diagnose(ctx, "terminating-ns")
	if err != nil {
		t.Fatalf("Diagnose failed: %v", err)
	}

	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}

	// Remediate Dry-Run
	dryResults, err := neutralizer.Remediate(ctx, candidates, true)
	if err != nil {
		t.Fatalf("Remediate dry-run failed: %v", err)
	}
	if len(dryResults) != 2 || !dryResults[0].DryRun || !dryResults[0].Success {
		t.Fatalf("unexpected dry-run results: %+v", dryResults)
	}

	// Remediate Live
	liveResults, err := neutralizer.Remediate(ctx, candidates, false)
	if err != nil {
		t.Fatalf("Remediate live failed: %v", err)
	}
	if len(liveResults) != 2 || liveResults[0].DryRun || !liveResults[0].Success {
		t.Fatalf("unexpected live results: %+v", liveResults)
	}
}
