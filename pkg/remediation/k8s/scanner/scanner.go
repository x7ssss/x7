package scanner

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
)

const (
	// DefaultListLimit is the server-side pagination page size to prevent client OOM.
	DefaultListLimit = 500
)

// ScannedResource represents a lingering Kubernetes object found in the target namespace.
type ScannedResource struct {
	GVR    schema.GroupVersionResource `json:"gvr"`
	Object unstructured.Unstructured   `json:"object"`
}

// ScanReport contains all lingering objects found across all discovered namespaced API groups.
type ScanReport struct {
	Namespace   string                      `json:"namespace"`
	TotalFound  int                         `json:"totalFound"`
	Resources   []ScannedResource           `json:"resources"`
	ScannedGVRs []schema.GroupVersionResource `json:"scannedGVRs"`
	Warnings    []string                    `json:"warnings,omitempty"`
}

// ResourceScanner scans all namespaced GroupVersionResources using dynamic client with server-side pagination.
type ResourceScanner struct {
	discoveryClient discovery.DiscoveryInterface
	dynamicClient   dynamic.Interface
	pageSize        int64
}

// NewResourceScanner creates a new ResourceScanner.
func NewResourceScanner(discoveryClient discovery.DiscoveryInterface, dynamicClient dynamic.Interface, pageSize int64) *ResourceScanner {
	if pageSize <= 0 {
		pageSize = DefaultListLimit
	}
	return &ResourceScanner{
		discoveryClient: discoveryClient,
		dynamicClient:   dynamicClient,
		pageSize:        pageSize,
	}
}

// DiscoverNamespacedGVRs discovers all namespaced GroupVersionResources supported by the cluster.
func (s *ResourceScanner) DiscoverNamespacedGVRs() ([]schema.GroupVersionResource, []string, error) {
	var warnings []string
	var gvrs []schema.GroupVersionResource
	seenGVR := make(map[schema.GroupVersionResource]bool)

	resourceLists, err := s.discoveryClient.ServerPreferredResources()
	if err != nil {
		if discovery.IsGroupDiscoveryFailedError(err) {
			if groupErr, ok := err.(*discovery.ErrGroupDiscoveryFailed); ok {
				for gv, gvErr := range groupErr.Groups {
					warnings = append(warnings, fmt.Sprintf("discovery warning for group %s: %v", gv.String(), gvErr))
				}
			}
		} else {
			return nil, warnings, fmt.Errorf("failed to discover server preferred resources: %w", err)
		}
	}

	for _, resourceList := range resourceLists {
		gv, err := schema.ParseGroupVersion(resourceList.GroupVersion)
		if err != nil {
			continue
		}

		for _, apiResource := range resourceList.APIResources {
			// Filter: only namespaced resources
			if !apiResource.Namespaced {
				continue
			}

			// Filter: subresources (e.g., pods/status, pods/log, bindings)
			if strings.Contains(apiResource.Name, "/") {
				continue
			}

			// Filter: must support 'list'
			supportsList := false
			for _, verb := range apiResource.Verbs {
				if verb == "list" {
					supportsList = true
					break
				}
			}
			if !supportsList {
				continue
			}

			gvr := schema.GroupVersionResource{
				Group:    gv.Group,
				Version:  gv.Version,
				Resource: apiResource.Name,
			}

			if !seenGVR[gvr] {
				seenGVR[gvr] = true
				gvrs = append(gvrs, gvr)
			}
		}
	}

	return gvrs, warnings, nil
}

// ScanNamespace exhaustively scans the target namespace for all lingering objects across all discovered GVRs.
func (s *ResourceScanner) ScanNamespace(ctx context.Context, targetNamespace string) (*ScanReport, error) {
	gvrs, warnings, err := s.DiscoverNamespacedGVRs()
	if err != nil {
		return nil, fmt.Errorf("failed to discover GVRs: %w", err)
	}

	report := &ScanReport{
		Namespace:   targetNamespace,
		ScannedGVRs: gvrs,
		Warnings:    warnings,
	}

	for _, gvr := range gvrs {
		var continueToken string
		for {
			listOpts := metav1.ListOptions{
				Limit:    s.pageSize,
				Continue: continueToken,
			}

			uList, err := s.dynamicClient.Resource(gvr).Namespace(targetNamespace).List(ctx, listOpts)
			if err != nil {
				// Record warning and proceed to next GVR (e.g. 403 Forbidden or broken API)
				report.Warnings = append(report.Warnings, fmt.Sprintf("Failed to list %s in namespace %s: %v", gvr.Resource, targetNamespace, err))
				break
			}

			for _, item := range uList.Items {
				report.Resources = append(report.Resources, ScannedResource{
					GVR:    gvr,
					Object: item,
				})
			}

			continueToken = uList.GetContinue()
			if continueToken == "" {
				break
			}
		}
	}

	report.TotalFound = len(report.Resources)
	return report, nil
}
