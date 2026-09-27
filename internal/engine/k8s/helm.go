package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/x7ssss/x7/pkg/triage"
)

// HelmEngine scans Secrets for Helm releases deadlocked in pending states.
type HelmEngine struct{}

func NewHelmEngine() *HelmEngine {
	return &HelmEngine{}
}

func (e *HelmEngine) Name() string {
	return "k8s-helm"
}

func (e *HelmEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemK8s
}

func (e *HelmEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	client, err := GetK8sClient()
	if err != nil {
		return []triage.DiagnosticResult{
			{
				ID:         "k8s-helm-unconfigured",
				Subsystem:  triage.SubsystemK8s,
				Target:     "Helm Releases",
				Severity:   triage.SeverityOK,
				Summary:    "No active Kubernetes cluster configured; check skipped",
				Details:    err.Error(),
				Remediable: false,
			},
		}, nil
	}

	secretsRaw, err := client.Get(ctx, "/api/v1/secrets?labelSelector=owner%3Dhelm")
	if err != nil {
		return nil, err
	}

	var secrets K8sSecretList
	if jsonErr := json.Unmarshal(secretsRaw, &secrets); jsonErr != nil {
		return nil, fmt.Errorf("failed to parse helm secrets json: %w", jsonErr)
	}

	results := make([]triage.DiagnosticResult, 0)

	for _, sec := range secrets.Items {
		labels := sec.Metadata.Labels
		status := labels["status"]
		releaseName := labels["name"]
		version := labels["version"]
		ns := sec.Metadata.Namespace
		secName := sec.Metadata.Name

		if strings.HasPrefix(status, "pending-") {
			secretNamespace := ns
			targetName := secName
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("k8s-helm-%s-%s", ns, releaseName),
				Subsystem:  triage.SubsystemK8s,
				Target:     fmt.Sprintf("Helm Release '%s' (ns: %s, rev: %s)", releaseName, ns, version),
				Severity:   triage.SeverityDeadlock,
				Summary:    fmt.Sprintf("Release deadlocked in state '%s'", status),
				Details:    fmt.Sprintf("Secret '%s' in namespace '%s' is locked in state '%s'", secName, ns, status),
				Remediable: true,
				RemediateFn: func(remCtx context.Context, dryRun bool) error {
					if dryRun {
						return nil
					}
					patch := []byte(`{"metadata":{"labels":{"status":"failed"}}}`)
					path := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", secretNamespace, targetName)
					_, patchErr := client.Patch(remCtx, path, "application/strategic-merge-patch+json", patch)
					return patchErr
				},
			})
		}
	}

	if len(results) == 0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "k8s-helm-nominal",
			Subsystem:  triage.SubsystemK8s,
			Target:     "Helm Releases",
			Severity:   triage.SeverityOK,
			Summary:    "No pending-install, pending-upgrade, or pending-rollback deadlocks detected",
			Remediable: false,
		})
	}

	return results, nil
}
