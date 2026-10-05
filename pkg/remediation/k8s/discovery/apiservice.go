package discovery

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

// APIServiceIssue describes an aggregated API service that is broken or unresolvable.
type APIServiceIssue struct {
	Name                   string `json:"name"`
	Group                  string `json:"group"`
	Version                string `json:"version"`
	ServiceNamespace       string `json:"serviceNamespace,omitempty"`
	ServiceName            string `json:"serviceName,omitempty"`
	Reason                 string `json:"reason,omitempty"`
	Message                string `json:"message,omitempty"`
	CausedDiscoveryFailure bool   `json:"causedDiscoveryFailure"`
	PointsToTargetNS       bool   `json:"pointsToTargetNamespace"`
	Dead                   bool   `json:"dead"`
}

// APIServiceRemediationResult describes the outcome of an APIService remediation action.
type APIServiceRemediationResult struct {
	APIServiceName string `json:"apiServiceName"`
	Action         string `json:"action"`
	DryRun         bool   `json:"dryRun"`
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	Error          string `json:"error,omitempty"`
}

// APIServiceTriager identifies and cleans up dead APIServices blocking namespace deletion.
type APIServiceTriager struct {
	discoveryClient  discovery.DiscoveryInterface
	aggregatorClient aggregatorclient.Interface
}

// NewAPIServiceTriager creates a new APIServiceTriager.
func NewAPIServiceTriager(discoveryClient discovery.DiscoveryInterface, aggregatorClient aggregatorclient.Interface) *APIServiceTriager {
	return &APIServiceTriager{
		discoveryClient:  discoveryClient,
		aggregatorClient: aggregatorClient,
	}
}

// Diagnose checks discovery errors and queries APIServices to find dead services blocking the namespace.
func (t *APIServiceTriager) Diagnose(ctx context.Context, targetNamespace string) ([]APIServiceIssue, error) {
	var issues []APIServiceIssue

	// 1. Run ServerPreferredResources discovery and check for GroupDiscoveryFailedError
	failedGroups := make(map[schema.GroupVersion]error)
	_, err := t.discoveryClient.ServerPreferredResources()
	if err != nil {
		if discovery.IsGroupDiscoveryFailedError(err) {
			if groupErr, ok := err.(*discovery.ErrGroupDiscoveryFailed); ok {
				for gv, gvErr := range groupErr.Groups {
					failedGroups[gv] = gvErr
				}
			}
		}
	}

	// 2. Fetch all APIServices
	apiServices, err := t.aggregatorClient.ApiregistrationV1().APIServices().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list APIServices: %w", err)
	}

	for _, apiService := range apiServices.Items {
		// Local / core services without spec.Service are internal apiserver endpoints
		var serviceNS, serviceName string
		pointsToTargetNS := false
		if apiService.Spec.Service != nil {
			serviceNS = apiService.Spec.Service.Namespace
			serviceName = apiService.Spec.Service.Name
			if strings.EqualFold(serviceNS, targetNamespace) {
				pointsToTargetNS = true
			}
		}

		gv := schema.GroupVersion{
			Group:   apiService.Spec.Group,
			Version: apiService.Spec.Version,
		}

		_, isFailedGroup := failedGroups[gv]

		// Check Available condition
		var isAvailableFalse bool
		var conditionReason, conditionMsg string
		for _, cond := range apiService.Status.Conditions {
			if cond.Type == apiregistrationv1.Available {
				if cond.Status == apiregistrationv1.ConditionFalse {
					isAvailableFalse = true
					conditionReason = cond.Reason
					conditionMsg = cond.Message
				}
				break
			}
		}

		// A dead APIService is one that:
		// 1) Reports Available=False
		// 2) Or belongs to a group whose discovery failed
		// 3) Or points to a service inside the target namespace that is not Available=True
		if isAvailableFalse || isFailedGroup || (pointsToTargetNS && isAvailableFalse) {
			issue := APIServiceIssue{
				Name:                   apiService.Name,
				Group:                  apiService.Spec.Group,
				Version:                apiService.Spec.Version,
				ServiceNamespace:       serviceNS,
				ServiceName:            serviceName,
				Reason:                 conditionReason,
				Message:                conditionMsg,
				CausedDiscoveryFailure: isFailedGroup,
				PointsToTargetNS:       pointsToTargetNS,
				Dead:                   true,
			}
			issues = append(issues, issue)
		}
	}

	return issues, nil
}

// Remediate removes dead APIServices that are stalling namespace deletion.
func (t *APIServiceTriager) Remediate(ctx context.Context, issues []APIServiceIssue, dryRun bool) ([]APIServiceRemediationResult, error) {
	var results []APIServiceRemediationResult

	for _, issue := range issues {
		if !issue.Dead {
			continue
		}

		if dryRun {
			results = append(results, APIServiceRemediationResult{
				APIServiceName: issue.Name,
				Action:         "DELETE",
				DryRun:         true,
				Success:        true,
				Message: fmt.Sprintf("Plan to delete dead APIService %s (group: %s/%s, reason: %s)",
					issue.Name, issue.Group, issue.Version, issue.Reason),
			})
			continue
		}

		// Live execution: delete APIService
		err := t.aggregatorClient.ApiregistrationV1().APIServices().Delete(ctx, issue.Name, metav1.DeleteOptions{})
		if err != nil {
			results = append(results, APIServiceRemediationResult{
				APIServiceName: issue.Name,
				Action:         "DELETE",
				DryRun:         false,
				Success:        false,
				Message:        fmt.Sprintf("Failed to delete dead APIService %s", issue.Name),
				Error:          err.Error(),
			})
		} else {
			results = append(results, APIServiceRemediationResult{
				APIServiceName: issue.Name,
				Action:         "DELETE",
				DryRun:         false,
				Success:        true,
				Message: fmt.Sprintf("Successfully deleted dead APIService %s to unfreeze namespace controller discovery",
					issue.Name),
			})
		}
	}

	return results, nil
}
