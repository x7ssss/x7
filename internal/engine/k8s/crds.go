package k8s

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/x7ssss/x7/pkg/triage"
)

// CRDEngine audits CRDs stuck in deletion with orphaned custom resources lingering in etcd.
type CRDEngine struct{}

func NewCRDEngine() *CRDEngine {
	return &CRDEngine{}
}

func (e *CRDEngine) Name() string {
	return "k8s-crds"
}

func (e *CRDEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemK8s
}

func (e *CRDEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	client, err := GetK8sClient()
	if err != nil {
		return []triage.DiagnosticResult{
			{
				ID:         "k8s-crds-unconfigured",
				Subsystem:  triage.SubsystemK8s,
				Target:     "CustomResourceDefinitions",
				Severity:   triage.SeverityOK,
				Summary:    "No active Kubernetes cluster configured; check skipped",
				Details:    err.Error(),
				Remediable: false,
			},
		}, nil
	}

	crdsRaw, err := client.Get(ctx, "/apis/apiextensions.k8s.io/v1/customresourcedefinitions")
	if err != nil {
		return nil, err
	}

	var crdList K8sCRDList
	if jsonErr := json.Unmarshal(crdsRaw, &crdList); jsonErr != nil {
		return nil, fmt.Errorf("failed to parse crd json: %w", jsonErr)
	}

	results := make([]triage.DiagnosticResult, 0)

	for _, crd := range crdList.Items {
		if crd.Metadata.DeletionTimestamp == nil {
			continue
		}

		crdName := crd.Metadata.Name
		group := crd.Spec.Group
		plural := crd.Spec.Names.Plural
		version := "v1"
		if len(crd.Spec.Versions) > 0 && crd.Spec.Versions[0].Name != "" {
			version = crd.Spec.Versions[0].Name
		}

		instancePath := fmt.Sprintf("/apis/%s/%s/%s", group, version, plural)
		instancesRaw, listErr := client.Get(ctx, instancePath)
		orphanCount := 0
		var instanceList K8sCustomResourceList
		if listErr == nil {
			if jsonErr := json.Unmarshal(instancesRaw, &instanceList); jsonErr == nil {
				orphanCount = len(instanceList.Items)
			}
		}

		targetCRD := crdName
		targetPlural := plural
		targetGroup := group
		targetVersion := version
		results = append(results, triage.DiagnosticResult{
			ID:         fmt.Sprintf("k8s-crd-%s", crdName),
			Subsystem:  triage.SubsystemK8s,
			Target:     fmt.Sprintf("CRD '%s'", crdName),
			Severity:   triage.SeverityDeadlock,
			Summary:    fmt.Sprintf("CRD stuck in deletion with %d orphaned custom resources lingering in etcd", orphanCount),
			Details:    fmt.Sprintf("Group: %s, Resource: %s, DeletionTimestamp: %s", group, plural, *crd.Metadata.DeletionTimestamp),
			Remediable: true,
			RemediateFn: func(remCtx context.Context, dryRun bool) error {
				if dryRun {
					return nil
				}
				// Remove finalizers from orphaned resources
				patch := []byte(`{"metadata":{"finalizers":[]}}`)
				for _, item := range instanceList.Items {
					var itemPath string
					if item.Metadata.Namespace != "" {
						itemPath = fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s/%s", targetGroup, targetVersion, item.Metadata.Namespace, targetPlural, item.Metadata.Name)
					} else {
						itemPath = fmt.Sprintf("/apis/%s/%s/%s/%s", targetGroup, targetVersion, targetPlural, item.Metadata.Name)
					}
					_, _ = client.Patch(remCtx, itemPath, "application/merge-patch+json", patch)
				}
				// Remove finalizers from the CRD itself
				crdPath := fmt.Sprintf("/apis/apiextensions.k8s.io/v1/customresourcedefinitions/%s", targetCRD)
				_, patchErr := client.Patch(remCtx, crdPath, "application/merge-patch+json", patch)
				return patchErr
			},
		})
	}

	if len(results) == 0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "k8s-crds-nominal",
			Subsystem:  triage.SubsystemK8s,
			Target:     "CustomResourceDefinitions",
			Severity:   triage.SeverityOK,
			Summary:    "No CRDs stuck in deletion with orphaned custom resources",
			Remediable: false,
		})
	}

	return results, nil
}
