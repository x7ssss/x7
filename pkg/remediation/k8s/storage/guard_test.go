package storage

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestBuildOutOfServiceTaintPatch(t *testing.T) {
	patch := BuildOutOfServiceTaintPatch()
	var parsed map[string]interface{}
	if err := json.Unmarshal(patch, &parsed); err != nil {
		t.Fatalf("failed to unmarshal taint patch JSON: %v", err)
	}

	spec, ok := parsed["spec"].(map[string]interface{})
	if !ok {
		t.Fatalf("spec field missing: %+v", parsed)
	}

	taints, ok := spec["taints"].([]interface{})
	if !ok || len(taints) != 1 {
		t.Fatalf("expected 1 taint in patch, got: %+v", spec["taints"])
	}

	taint := taints[0].(map[string]interface{})
	if taint["key"] != OutOfServiceTaintKey {
		t.Errorf("expected key %s, got %v", OutOfServiceTaintKey, taint["key"])
	}
	if taint["value"] != OutOfServiceTaintValue {
		t.Errorf("expected value %s, got %v", OutOfServiceTaintValue, taint["value"])
	}
	if taint["effect"] != string(OutOfServiceTaintEffect) {
		t.Errorf("expected effect %s, got %v", OutOfServiceTaintEffect, taint["effect"])
	}
}

func TestDiagnoseAndApplyDeadNodeStorageTaints(t *testing.T) {
	ctx := context.Background()
	nowTime := metav1.NewTime(time.Now())

	// 1. Stuck PVC with pvc-protection finalizer
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "data-pvc",
			Namespace:         "test-ns",
			DeletionTimestamp: &nowTime,
			Finalizers:        []string{"kubernetes.io/pvc-protection"},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			VolumeName: "pv-vol-01",
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase: corev1.ClaimBound,
		},
	}

	// 2. Pod mounted on dead node
	podDeadNode := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "workload-pod-dead",
			Namespace:         "test-ns",
			DeletionTimestamp: &nowTime,
		},
		Spec: corev1.PodSpec{
			NodeName: "node-crashed-01",
			Volumes: []corev1.Volume{
				{
					Name: "data",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: "data-pvc",
						},
					},
				},
			},
		},
	}

	// 3. Dead Node (Ready: False)
	deadNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-crashed-01",
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{
					Type:    corev1.NodeReady,
					Status:  corev1.ConditionFalse,
					Reason:  "KubeletNotResponding",
					Message: "node is unreachable",
				},
			},
		},
	}

	// 4. Healthy Node (Ready: True)
	healthyNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-healthy-02",
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{
					Type:   corev1.NodeReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}

	client := fake.NewSimpleClientset(pvc, podDeadNode, deadNode, healthyNode)

	// Diagnose
	candidates, err := DiagnoseDeadStorageNodes(ctx, client, "test-ns")
	if err != nil {
		t.Fatalf("DiagnoseDeadStorageNodes failed: %v", err)
	}

	if len(candidates) != 1 {
		t.Fatalf("expected 1 dead node candidate, got %d", len(candidates))
	}

	cand := candidates[0]
	if cand.NodeName != "node-crashed-01" {
		t.Errorf("expected node node-crashed-01, got %s", cand.NodeName)
	}
	if cand.PVCName != "data-pvc" {
		t.Errorf("expected PVC data-pvc, got %s", cand.PVCName)
	}

	// Apply Dry-Run
	dryResults, err := ApplyOutOfServiceTaints(ctx, client, candidates, true)
	if err != nil {
		t.Fatalf("ApplyOutOfServiceTaints dry run failed: %v", err)
	}
	if len(dryResults) != 1 || !dryResults[0].DryRun || !dryResults[0].Success {
		t.Fatalf("unexpected dry run result: %+v", dryResults)
	}

	// Apply Live
	liveResults, err := ApplyOutOfServiceTaints(ctx, client, candidates, false)
	if err != nil {
		t.Fatalf("ApplyOutOfServiceTaints live failed: %v", err)
	}
	if len(liveResults) != 1 || liveResults[0].DryRun || !liveResults[0].Success {
		t.Fatalf("unexpected live result: %+v", liveResults)
	}

	// Verify Node has taint applied
	updatedNode, err := client.CoreV1().Nodes().Get(ctx, "node-crashed-01", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to fetch updated node: %v", err)
	}

	hasTaint := false
	for _, tnt := range updatedNode.Spec.Taints {
		if tnt.Key == OutOfServiceTaintKey && tnt.Value == OutOfServiceTaintValue && tnt.Effect == OutOfServiceTaintEffect {
			hasTaint = true
			break
		}
	}
	if !hasTaint {
		t.Errorf("expected node to have out-of-service taint applied, got: %+v", updatedNode.Spec.Taints)
	}
}
