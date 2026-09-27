package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/x7ssss/x7/pkg/triage"
)

// GitOpsEngine evaluates admission drift and mutating webhook sync loops.
type GitOpsEngine struct{}

func NewGitOpsEngine() *GitOpsEngine {
	return &GitOpsEngine{}
}

func (e *GitOpsEngine) Name() string {
	return "k8s-gitops"
}

func (e *GitOpsEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemK8s
}

func (e *GitOpsEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	client, err := GetK8sClient()
	if err != nil {
		return []triage.DiagnosticResult{
			{
				ID:         "k8s-gitops-unconfigured",
				Subsystem:  triage.SubsystemK8s,
				Target:     "GitOps Deployments",
				Severity:   triage.SeverityOK,
				Summary:    "No active Kubernetes cluster configured; check skipped",
				Details:    err.Error(),
				Remediable: false,
			},
		}, nil
	}

	deploysRaw, err := client.Get(ctx, "/apis/apps/v1/deployments")
	if err != nil {
		return nil, err
	}

	var deploys K8sDeploymentList
	if jsonErr := json.Unmarshal(deploysRaw, &deploys); jsonErr != nil {
		return nil, fmt.Errorf("failed to parse deployments json: %w", jsonErr)
	}

	results := make([]triage.DiagnosticResult, 0)

	mutatingAnnotations := []string{
		"sidecar.istio.io/status",
		"linkerd.io/injected",
		"vault.hashicorp.com/agent-inject-status",
		"admission.datadoghq.com/java-lib.version",
	}

	for _, d := range deploys.Items {
		name := d.Metadata.Name
		ns := d.Metadata.Namespace
		annotations := d.Metadata.Annotations

		hasMutatingWebhook := false
		var matchedAnnotations []string
		for _, ann := range mutatingAnnotations {
			if _, found := annotations[ann]; found {
				hasMutatingWebhook = true
				matchedAnnotations = append(matchedAnnotations, ann)
			}
		}

		hasGitOps := false
		for k := range annotations {
			if strings.Contains(k, "argocd.argoproj.io") || strings.Contains(k, "fluxcd.io") {
				hasGitOps = true
				break
			}
		}

		gen := d.Metadata.Generation
		obsGen := d.Status.ObservedGeneration

		if hasGitOps && hasMutatingWebhook && (gen != obsGen || len(matchedAnnotations) > 0) {
			deployName := name
			deployNamespace := ns
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("k8s-gitops-%s-%s", ns, name),
				Subsystem:  triage.SubsystemK8s,
				Target:     fmt.Sprintf("Deployment '%s/%s'", ns, name),
				Severity:   triage.SeverityWarning,
				Summary:    "Potential mutating webhook sync loop detected under GitOps controller",
				Details:    fmt.Sprintf("Mutating annotations [%s] present on GitOps-managed workload; generation: %d, observedGeneration: %d", strings.Join(matchedAnnotations, ", "), gen, obsGen),
				Remediable: true,
				RemediateFn: func(remCtx context.Context, dryRun bool) error {
					if dryRun {
						return nil
					}
					patch := []byte(`{"metadata":{"annotations":{"argocd.argoproj.io/compare-options":"IgnoreExtraneous"}}}`)
					path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", deployNamespace, deployName)
					_, patchErr := client.Patch(remCtx, path, "application/strategic-merge-patch+json", patch)
					return patchErr
				},
			})
		}
	}

	if len(results) == 0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "k8s-gitops-nominal",
			Subsystem:  triage.SubsystemK8s,
			Target:     "Deployments Admission",
			Severity:   triage.SeverityOK,
			Summary:    "No mutating webhook sync loops or admission drift detected",
			Remediable: false,
		})
	}

	return results, nil
}
