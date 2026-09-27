package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/x7ssss/x7/pkg/triage"
)

// UnstuckEngine detects namespaces stuck in Terminating and failing APIServices.
type UnstuckEngine struct{}

func NewUnstuckEngine() *UnstuckEngine {
	return &UnstuckEngine{}
}

func (e *UnstuckEngine) Name() string {
	return "k8s-unstuck"
}

func (e *UnstuckEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemK8s
}

func (e *UnstuckEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	client, err := GetK8sClient()
	if err != nil {
		return []triage.DiagnosticResult{
			{
				ID:         "k8s-unstuck-unconfigured",
				Subsystem:  triage.SubsystemK8s,
				Target:     "Cluster API",
				Severity:   triage.SeverityOK,
				Summary:    "No active Kubernetes cluster configured; check skipped",
				Details:    err.Error(),
				Remediable: false,
			},
		}, nil
	}

	results := make([]triage.DiagnosticResult, 0)

	// 1. Inspect failing APIServices that poison discovery
	apiServicesRaw, err := client.Get(ctx, "/apis/apiregistration.k8s.io/v1/apiservices")
	if err == nil {
		var apiServices K8sAPIServiceList
		if jsonErr := json.Unmarshal(apiServicesRaw, &apiServices); jsonErr == nil {
			for _, item := range apiServices.Items {
				name := item.Metadata.Name
				for _, cond := range item.Status.Conditions {
					if cond.Type == "Available" && cond.Status != "True" {
						svcName := name
						results = append(results, triage.DiagnosticResult{
							ID:         fmt.Sprintf("k8s-apisvc-%s", name),
							Subsystem:  triage.SubsystemK8s,
							Target:     fmt.Sprintf("APIService '%s'", name),
							Severity:   triage.SeverityDeadlock,
							Summary:    "Failing APIService poisoning discovery and blocking deletion",
							Details:    fmt.Sprintf("APIService condition Available=%s: %s (Reason: %s)", cond.Status, cond.Message, cond.Reason),
							Remediable: true,
							RemediateFn: func(remCtx context.Context, dryRun bool) error {
								if dryRun {
									return nil
								}
								return client.Delete(remCtx, "/apis/apiregistration.k8s.io/v1/apiservices/"+svcName)
							},
						})
					}
				}
			}
		}
	}

	// 2. Inspect namespaces stuck in Terminating
	nsRaw, err := client.Get(ctx, "/api/v1/namespaces")
	if err != nil {
		return results, err
	}

	var namespaces K8sNamespaceList
	if jsonErr := json.Unmarshal(nsRaw, &namespaces); jsonErr != nil {
		return results, fmt.Errorf("failed to parse namespaces json: %w", jsonErr)
	}

	for _, ns := range namespaces.Items {
		name := ns.Metadata.Name
		isTerminating := ns.Metadata.DeletionTimestamp != nil || ns.Status.Phase == "Terminating"
		if !isTerminating {
			continue
		}

		hasDiscoveryFailure := false
		var conditionMessages []string
		for _, cond := range ns.Status.Conditions {
			if strings.Contains(cond.Type, "DiscoveryFailure") || cond.Type == "NamespaceDeletionDiscoveryFailure" {
				if cond.Status == "True" {
					hasDiscoveryFailure = true
				}
			}
			if cond.Status == "True" {
				conditionMessages = append(conditionMessages, fmt.Sprintf("%s: %s", cond.Type, cond.Message))
			}
		}

		summary := "Namespace stuck in Terminating phase"
		if hasDiscoveryFailure {
			summary = "Namespace deletion deadlocked by DiscoveryFailure (poisoned APIService)"
		}

		nsName := name
		results = append(results, triage.DiagnosticResult{
			ID:         fmt.Sprintf("k8s-ns-%s", name),
			Subsystem:  triage.SubsystemK8s,
			Target:     fmt.Sprintf("Namespace '%s'", name),
			Severity:   triage.SeverityDeadlock,
			Summary:    summary,
			Details:    strings.Join(conditionMessages, "; "),
			Remediable: true,
			RemediateFn: func(remCtx context.Context, dryRun bool) error {
				if dryRun {
					return nil
				}
				patchData := []byte(`{"spec":{"finalizers":[]}}`)
				// Finalize endpoint strips finalizers
				_, patchErr := client.Patch(remCtx, "/api/v1/namespaces/"+nsName+"/finalize", "application/json", patchData)
				if patchErr != nil {
					_, patchErr = client.Patch(remCtx, "/api/v1/namespaces/"+nsName, "application/strategic-merge-patch+json", patchData)
				}
				return patchErr
			},
		})
	}

	if len(results) == 0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "k8s-unstuck-nominal",
			Subsystem:  triage.SubsystemK8s,
			Target:     "Namespaces",
			Severity:   triage.SeverityOK,
			Summary:    "No terminating namespaces or failing APIServices detected",
			Remediable: false,
		})
	}

	return results, nil
}
