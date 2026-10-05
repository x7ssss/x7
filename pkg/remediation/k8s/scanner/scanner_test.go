package scanner

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	fakedynamic "k8s.io/client-go/dynamic/fake"
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

func TestResourceScanner_DiscoverNamespacedGVRs(t *testing.T) {
	mockDisc := &mockDiscovery{
		serverPreferredResourcesFn: func() ([]*metav1.APIResourceList, error) {
			return []*metav1.APIResourceList{
				{
					GroupVersion: "v1",
					APIResources: []metav1.APIResource{
						{
							Name:       "pods",
							Namespaced: true,
							Verbs:      []string{"get", "list", "watch", "delete"},
						},
						{
							Name:       "pods/status",
							Namespaced: true,
							Verbs:      []string{"get", "patch", "update"},
						},
						{
							Name:       "nodes",
							Namespaced: false, // Cluster scoped
							Verbs:      []string{"get", "list"},
						},
						{
							Name:       "bindings",
							Namespaced: true,
							Verbs:      []string{"create"}, // No list verb
						},
					},
				},
				{
					GroupVersion: "apps/v1",
					APIResources: []metav1.APIResource{
						{
							Name:       "deployments",
							Namespaced: true,
							Verbs:      []string{"get", "list", "delete"},
						},
					},
				},
			}, nil
		},
	}

	scheme := runtime.NewScheme()
	fakeDyn := fakedynamic.NewSimpleDynamicClient(scheme)
	scanner := NewResourceScanner(mockDisc, fakeDyn, 500)

	gvrs, warnings, err := scanner.DiscoverNamespacedGVRs()
	if err != nil {
		t.Fatalf("DiscoverNamespacedGVRs failed: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}

	// Should only have pods (v1) and deployments (apps/v1)
	if len(gvrs) != 2 {
		t.Fatalf("expected 2 GVRs, got %d: %+v", len(gvrs), gvrs)
	}

	expectedGVRs := map[schema.GroupVersionResource]bool{
		{Group: "", Version: "v1", Resource: "pods"}:             true,
		{Group: "apps", Version: "v1", Resource: "deployments"}: true,
	}

	for _, gvr := range gvrs {
		if !expectedGVRs[gvr] {
			t.Errorf("unexpected GVR discovered: %v", gvr)
		}
	}
}

func TestResourceScanner_ScanNamespace(t *testing.T) {
	ctx := context.Background()

	mockDisc := &mockDiscovery{
		serverPreferredResourcesFn: func() ([]*metav1.APIResourceList, error) {
			return []*metav1.APIResourceList{
				{
					GroupVersion: "v1",
					APIResources: []metav1.APIResource{
						{
							Name:       "configmaps",
							Namespaced: true,
							Verbs:      []string{"get", "list", "delete"},
						},
					},
				},
			}, nil
		},
	}

	cm1 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "cm-in-target",
				"namespace": "target-ns",
			},
		},
	}
	cm2 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "cm-in-other",
				"namespace": "other-ns",
			},
		},
	}

	scheme := runtime.NewScheme()
	fakeDyn := fakedynamic.NewSimpleDynamicClient(scheme, cm1, cm2)

	scanner := NewResourceScanner(mockDisc, fakeDyn, 10)
	report, err := scanner.ScanNamespace(ctx, "target-ns")
	if err != nil {
		t.Fatalf("ScanNamespace failed: %v", err)
	}

	if report.TotalFound != 1 {
		t.Fatalf("expected 1 resource found in target-ns, got %d", report.TotalFound)
	}
	if report.Resources[0].Object.GetName() != "cm-in-target" {
		t.Errorf("expected resource cm-in-target, got %s", report.Resources[0].Object.GetName())
	}
}
