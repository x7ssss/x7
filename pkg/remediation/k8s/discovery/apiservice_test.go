package discovery

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	fakeaggregator "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
)

type mockDiscovery struct {
	discovery.DiscoveryInterface
	serverPreferredResourcesFn func() ([]*metav1.APIResourceList, error)
}

func (m *mockDiscovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	if m.serverPreferredResourcesFn != nil {
		return m.serverPreferredResourcesFn()
	}
	return nil, nil
}

func TestAPIServiceTriager_DiagnoseAndRemediate(t *testing.T) {
	ctx := context.Background()

	// 1. Setup mock discovery that reports GroupDiscoveryFailedError for "custom.metrics.k8s.io/v1beta1"
	failedGV := schema.GroupVersion{Group: "custom.metrics.k8s.io", Version: "v1beta1"}
	groupErr := &discovery.ErrGroupDiscoveryFailed{
		Groups: map[schema.GroupVersion]error{
			failedGV: errors.New("service unavailable 503"),
		},
	}

	mockDisc := &mockDiscovery{
		serverPreferredResourcesFn: func() ([]*metav1.APIResourceList, error) {
			return nil, groupErr
		},
	}

	// 2. Setup fake aggregator clientset with healthy and dead APIServices
	healthyAPIService := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: "v1.apps",
		},
		Spec: apiregistrationv1.APIServiceSpec{
			Group:   "apps",
			Version: "v1",
		},
		Status: apiregistrationv1.APIServiceStatus{
			Conditions: []apiregistrationv1.APIServiceCondition{
				{
					Type:   apiregistrationv1.Available,
					Status: apiregistrationv1.ConditionTrue,
				},
			},
		},
	}

	deadMetricsAPIService := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: "v1beta1.custom.metrics.k8s.io",
		},
		Spec: apiregistrationv1.APIServiceSpec{
			Group:   "custom.metrics.k8s.io",
			Version: "v1beta1",
			Service: &apiregistrationv1.ServiceReference{
				Namespace: "stuck-namespace",
				Name:      "custom-metrics-adapter",
			},
		},
		Status: apiregistrationv1.APIServiceStatus{
			Conditions: []apiregistrationv1.APIServiceCondition{
				{
					Type:    apiregistrationv1.Available,
					Status:  apiregistrationv1.ConditionFalse,
					Reason:  "ServiceNotFound",
					Message: "service stuck-namespace/custom-metrics-adapter does not exist",
				},
			},
		},
	}

	fakeAggregator := fakeaggregator.NewSimpleClientset(healthyAPIService, deadMetricsAPIService)

	triager := NewAPIServiceTriager(mockDisc, fakeAggregator)

	// Test Diagnose
	issues, err := triager.Diagnose(ctx, "stuck-namespace")
	if err != nil {
		t.Fatalf("Diagnose failed: %v", err)
	}

	if len(issues) != 1 {
		t.Fatalf("expected 1 dead APIService issue, got %d", len(issues))
	}

	issue := issues[0]
	if issue.Name != "v1beta1.custom.metrics.k8s.io" {
		t.Errorf("unexpected issue name: got %s, want v1beta1.custom.metrics.k8s.io", issue.Name)
	}
	if !issue.PointsToTargetNS {
		t.Errorf("expected PointsToTargetNS to be true")
	}
	if !issue.CausedDiscoveryFailure {
		t.Errorf("expected CausedDiscoveryFailure to be true")
	}
	if issue.Reason != "ServiceNotFound" {
		t.Errorf("unexpected reason: got %s, want ServiceNotFound", issue.Reason)
	}

	// Test Remediate with dryRun = true
	dryResults, err := triager.Remediate(ctx, issues, true)
	if err != nil {
		t.Fatalf("dry-run remediate failed: %v", err)
	}
	if len(dryResults) != 1 || !dryResults[0].DryRun || !dryResults[0].Success {
		t.Fatalf("unexpected dry run result: %+v", dryResults)
	}

	// Verify APIService is still present in cluster after dry-run
	svc, err := fakeAggregator.ApiregistrationV1().APIServices().Get(ctx, deadMetricsAPIService.Name, metav1.GetOptions{})
	if err != nil || svc == nil {
		t.Fatalf("APIService was unexpectedly deleted during dry-run")
	}

	// Test Remediate with dryRun = false (live)
	liveResults, err := triager.Remediate(ctx, issues, false)
	if err != nil {
		t.Fatalf("live remediate failed: %v", err)
	}
	if len(liveResults) != 1 || liveResults[0].DryRun || !liveResults[0].Success {
		t.Fatalf("unexpected live result: %+v", liveResults)
	}

	// Verify APIService is now deleted
	_, err = fakeAggregator.ApiregistrationV1().APIServices().Get(ctx, deadMetricsAPIService.Name, metav1.GetOptions{})
	if err == nil {
		t.Fatalf("expected APIService to be deleted, but it still exists")
	}
}
