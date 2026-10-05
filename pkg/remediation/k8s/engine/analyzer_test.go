package engine

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/x7ssss/x7/pkg/remediation/k8s/scanner"
)

func TestAnalyzer_Heuristics(t *testing.T) {
	ctx := context.Background()
	fixedNow := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)

	// Setup fake client without any active operator workloads in target namespace
	client := fake.NewSimpleClientset(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dead-operator",
			Namespace: "test-ns",
		},
		Status: appsv1.DeploymentStatus{
			ReadyReplicas: 0,
		},
	})

	analyzer := NewAnalyzer(client)
	analyzer.SetNowFunc(func() time.Time { return fixedNow })

	// Item 1: Graceful Deletion (< 5 min)
	gracefulTime := metav1.NewTime(fixedNow.Add(-2 * time.Minute))
	gracefulObj := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":              "recent-pod",
				"namespace":         "test-ns",
				"deletionTimestamp": gracefulTime.Format(time.RFC3339),
				"finalizers":        []interface{}{"kubernetes"},
			},
		},
	}

	// Item 2: Orphaned CRD (> 15 min, custom finalizers, 0 operator replicas)
	orphanedTime := metav1.NewTime(fixedNow.Add(-25 * time.Minute))
	crdObj := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "database.example.com/v1alpha1",
			"kind":       "PostgresCluster",
			"metadata": map[string]interface{}{
				"name":              "my-pg",
				"namespace":         "test-ns",
				"deletionTimestamp": orphanedTime.Format(time.RFC3339),
				"finalizers":        []interface{}{"postgrescluster.database.example.com/finalizer"},
			},
		},
	}

	// Item 3: Storage Detach Stall (PVC with pvc-protection finalizer)
	pvcTime := metav1.NewTime(fixedNow.Add(-30 * time.Minute))
	pvcObj := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "PersistentVolumeClaim",
			"metadata": map[string]interface{}{
				"name":              "data-pvc",
				"namespace":         "test-ns",
				"deletionTimestamp": pvcTime.Format(time.RFC3339),
				"finalizers":        []interface{}{"kubernetes.io/pvc-protection"},
			},
			"spec": map[string]interface{}{
				"volumeName": "pvc-12345-pv",
			},
		},
	}

	// Item 4: Generic Deadlocked Child (> 5 min, finalizers present)
	genericTime := metav1.NewTime(fixedNow.Add(-8 * time.Minute))
	genericObj := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":              "stuck-cm",
				"namespace":         "test-ns",
				"deletionTimestamp": genericTime.Format(time.RFC3339),
				"finalizers":        []interface{}{"custom.io/cleanup-blocker"},
			},
		},
	}

	items := []scanner.ScannedResource{
		{
			GVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			Object: gracefulObj,
		},
		{
			GVR:    schema.GroupVersionResource{Group: "database.example.com", Version: "v1alpha1", Resource: "postgresclusters"},
			Object: crdObj,
		},
		{
			GVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "persistentvolumeclaims"},
			Object: pvcObj,
		},
		{
			GVR:    schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"},
			Object: genericObj,
		},
	}

	analyses, err := analyzer.Analyze(ctx, "test-ns", items)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(analyses) != 4 {
		t.Fatalf("expected 4 analyses, got %d", len(analyses))
	}

	// Verify Item 1: Graceful Deletion
	if analyses[0].Category != CategoryGracefulDeletion || analyses[0].Action != ActionSkip {
		t.Errorf("expected GracefulDeletion & SKIP for item 0, got category %s action %s", analyses[0].Category, analyses[0].Action)
	}

	// Verify Item 2: Orphaned CRD
	if analyses[1].Category != CategoryOrphanedCRD || analyses[1].Action != ActionStripFinalizers {
		t.Errorf("expected OrphanedCRD & STRIP_FINALIZERS for item 1, got category %s action %s", analyses[1].Category, analyses[1].Action)
	}

	// Verify Item 3: Storage Detach Stall
	if analyses[2].Category != CategoryStorageDetach || analyses[2].Action != ActionFlagStorageStall {
		t.Errorf("expected StorageDetachStall & FLAG_STORAGE_STALL for item 2, got category %s action %s", analyses[2].Category, analyses[2].Action)
	}

	// Verify Item 4: Generic Deadlocked Child
	if analyses[3].Category != CategoryDeadlockedChild || analyses[3].Action != ActionStripFinalizers {
		t.Errorf("expected DeadlockedChild & STRIP_FINALIZERS for item 3, got category %s action %s", analyses[3].Category, analyses[3].Action)
	}
}
