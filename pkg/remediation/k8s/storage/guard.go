package storage

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const (
	OutOfServiceTaintKey    = "node.kubernetes.io/out-of-service"
	OutOfServiceTaintValue  = "nodeshutdown"
	OutOfServiceTaintEffect = corev1.TaintEffectNoExecute
)

// DeadNodeStorageCandidate identifies a dead cluster node hosting terminating pods with stuck PVCs.
type DeadNodeStorageCandidate struct {
	NodeName      string `json:"nodeName"`
	PodName       string `json:"podName"`
	PVCName       string `json:"pvcName"`
	VolumeName    string `json:"volumeName,omitempty"`
	NodeCondition string `json:"nodeCondition"`
	NodeReason    string `json:"nodeReason,omitempty"`
	TaintToApply  string `json:"taintToApply"`
}

// NodeTaintResult represents the outcome of applying the out-of-service taint.
type NodeTaintResult struct {
	NodeName string `json:"nodeName"`
	Action   string `json:"action"`
	DryRun   bool   `json:"dryRun"`
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Error    string `json:"error,omitempty"`
}

// BuildOutOfServiceTaintPatch returns the Strategic Merge Patch payload to apply node.kubernetes.io/out-of-service.
func BuildOutOfServiceTaintPatch() []byte {
	return []byte(`{"spec":{"taints":[{"key":"node.kubernetes.io/out-of-service","value":"nodeshutdown","effect":"NoExecute"}]}}`)
}

// DiagnoseDeadStorageNodes inspects PVCs, terminating pods, and backing node conditions to find dead nodes.
func DiagnoseDeadStorageNodes(ctx context.Context, client kubernetes.Interface, namespace string) ([]DeadNodeStorageCandidate, error) {
	var candidates []DeadNodeStorageCandidate

	// 1. List PVCs in terminating namespace
	pvcList, err := client.CoreV1().PersistentVolumeClaims(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list PVCs in %s: %w", namespace, err)
	}

	stuckPVCs := make(map[string]string) // pvcName -> volumeName
	for _, pvc := range pvcList.Items {
		hasProtection := false
		for _, f := range pvc.Finalizers {
			if f == "kubernetes.io/pvc-protection" {
				hasProtection = true
				break
			}
		}

		if hasProtection && pvc.DeletionTimestamp != nil {
			stuckPVCs[pvc.Name] = pvc.Spec.VolumeName
		}
	}

	if len(stuckPVCs) == 0 {
		return nil, nil
	}

	// 2. List Pods in namespace referencing stuck PVCs
	podList, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list Pods in %s: %w", namespace, err)
	}

	seenNode := make(map[string]bool)

	for _, pod := range podList.Items {
		if pod.Spec.NodeName == "" {
			continue
		}

		// Check if pod references one of the stuck PVCs
		var mountedPVC string
		for _, vol := range pod.Spec.Volumes {
			if vol.PersistentVolumeClaim != nil {
				if _, ok := stuckPVCs[vol.PersistentVolumeClaim.ClaimName]; ok {
					mountedPVC = vol.PersistentVolumeClaim.ClaimName
					break
				}
			}
		}

		if mountedPVC == "" {
			continue
		}

		nodeName := pod.Spec.NodeName
		if seenNode[nodeName] {
			continue
		}

		// Inspect Node status
		node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			continue
		}

		// Check NodeReady condition
		var isReady bool
		var conditionStatus corev1.ConditionStatus
		var conditionReason string
		for _, cond := range node.Status.Conditions {
			if cond.Type == corev1.NodeReady {
				conditionStatus = cond.Status
				conditionReason = cond.Reason
				if cond.Status == corev1.ConditionTrue {
					isReady = true
				}
				break
			}
		}

		// If node is not ready (False or Unknown)
		if !isReady {
			// Check if already tainted with out-of-service
			hasOutOfServiceTaint := false
			for _, t := range node.Spec.Taints {
				if t.Key == OutOfServiceTaintKey {
					hasOutOfServiceTaint = true
					break
				}
			}

			if !hasOutOfServiceTaint {
				seenNode[nodeName] = true
				candidates = append(candidates, DeadNodeStorageCandidate{
					NodeName:      nodeName,
					PodName:       pod.Name,
					PVCName:       mountedPVC,
					VolumeName:    stuckPVCs[mountedPVC],
					NodeCondition: fmt.Sprintf("Ready=%s", conditionStatus),
					NodeReason:    conditionReason,
					TaintToApply:  fmt.Sprintf("%s=%s:%s", OutOfServiceTaintKey, OutOfServiceTaintValue, OutOfServiceTaintEffect),
				})
			}
		}
	}

	return candidates, nil
}

// ApplyOutOfServiceTaints applies the official out-of-service taint to dead nodes to safely unblock storage detach.
func ApplyOutOfServiceTaints(ctx context.Context, client kubernetes.Interface, candidates []DeadNodeStorageCandidate, dryRun bool) ([]NodeTaintResult, error) {
	var results []NodeTaintResult
	processedNodes := make(map[string]bool)

	for _, c := range candidates {
		if processedNodes[c.NodeName] {
			continue
		}
		processedNodes[c.NodeName] = true

		if dryRun {
			results = append(results, NodeTaintResult{
				NodeName: c.NodeName,
				Action:   "APPLY_OUT_OF_SERVICE_TAINT",
				DryRun:   true,
				Success:  true,
				Message: fmt.Sprintf("Plan to apply safe out-of-service taint to dead node %s (%s, reason: %s) to release PVC %s volume lock without corruption",
					c.NodeName, c.NodeCondition, c.NodeReason, c.PVCName),
			})
			continue
		}

		// Live execution: fetch, append taint and update or patch
		patchData := BuildOutOfServiceTaintPatch()
		_, err := client.CoreV1().Nodes().Patch(ctx, c.NodeName, types.StrategicMergePatchType, patchData, metav1.PatchOptions{})
		if err != nil {
			// Fallback: try typed update if strategic merge patch fails on fake clients
			node, getErr := client.CoreV1().Nodes().Get(ctx, c.NodeName, metav1.GetOptions{})
			if getErr == nil {
				node.Spec.Taints = append(node.Spec.Taints, corev1.Taint{
					Key:    OutOfServiceTaintKey,
					Value:  OutOfServiceTaintValue,
					Effect: OutOfServiceTaintEffect,
				})
				_, err = client.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
			}
		}

		if err != nil {
			results = append(results, NodeTaintResult{
				NodeName: c.NodeName,
				Action:   "APPLY_OUT_OF_SERVICE_TAINT",
				DryRun:   false,
				Success:  false,
				Message:  fmt.Sprintf("Failed to taint dead node %s", c.NodeName),
				Error:    err.Error(),
			})
		} else {
			results = append(results, NodeTaintResult{
				NodeName: c.NodeName,
				Action:   "APPLY_OUT_OF_SERVICE_TAINT",
				DryRun:   false,
				Success:  true,
				Message: fmt.Sprintf("Successfully applied %s taint to dead node %s. Kube-controller-manager will safely detach volumes.",
					OutOfServiceTaintKey, c.NodeName),
			})
		}
	}

	return results, nil
}
