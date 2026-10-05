package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"

	"github.com/x7ssss/x7/pkg/remediation/k8s/scanner"
)

const (
	GracefulDeletionThreshold = 5 * time.Minute
	OrphanedCRDThreshold      = 15 * time.Minute
)

// Analyzer inspects lingering resources and applies diagnostic heuristics to determine deadlock causes.
type Analyzer struct {
	client            kubernetes.Interface
	nowFunc           func() time.Time
	gracefulThreshold time.Duration
	orphanedThreshold time.Duration
}

// NewAnalyzer creates a new diagnostic heuristic analyzer.
func NewAnalyzer(client kubernetes.Interface) *Analyzer {
	return &Analyzer{
		client:            client,
		nowFunc:           time.Now,
		gracefulThreshold: GracefulDeletionThreshold,
		orphanedThreshold: OrphanedCRDThreshold,
	}
}

// SetNowFunc allows overriding the current time for deterministic unit tests.
func (a *Analyzer) SetNowFunc(fn func() time.Time) {
	a.nowFunc = fn
}

// Analyze applies diagnostic heuristics to categorize all scanned objects.
func (a *Analyzer) Analyze(ctx context.Context, targetNamespace string, items []scanner.ScannedResource) ([]ResourceAnalysis, error) {
	var analyses []ResourceAnalysis
	now := a.nowFunc()

	// Check whether operator workloads exist in the target namespace
	operatorPresent, err := a.checkOperatorWorkloads(ctx, targetNamespace)
	if err != nil {
		operatorPresent = false
	}

	// Fetch VolumeAttachments once if checking storage stalls
	volumeAttachmentErrors := a.checkVolumeAttachmentErrors(ctx)

	for _, item := range items {
		analysis := a.analyzeItem(item, now, operatorPresent, volumeAttachmentErrors)
		analyses = append(analyses, analysis)
	}

	return analyses, nil
}

func (a *Analyzer) analyzeItem(
	item scanner.ScannedResource,
	now time.Time,
	operatorWorkloadsPresent bool,
	vaErrors map[string]string,
) ResourceAnalysis {
	obj := item.Object
	gvr := item.GVR
	name := obj.GetName()
	ns := obj.GetNamespace()
	kind := obj.GetKind()
	apiVersion := obj.GetAPIVersion()
	finalizers := obj.GetFinalizers()
	deletionTimestamp := obj.GetDeletionTimestamp()

	analysis := ResourceAnalysis{
		GVR:               gvr,
		Name:              name,
		Namespace:         ns,
		Kind:              kind,
		APIVersion:        apiVersion,
		DeletionTimestamp: deletionTimestamp,
		Finalizers:        finalizers,
		RawObject:         obj,
	}

	// Object not yet marked for deletion
	if deletionTimestamp == nil {
		analysis.Category = CategoryActiveResource
		analysis.Action = ActionInspect
		analysis.Reason = "Object has no deletionTimestamp; namespace controller may be blocked by earlier phases or discovery errors"
		return analysis
	}

	age := now.Sub(deletionTimestamp.Time)
	analysis.AgeSinceDeletion = age

	// Heuristic A: Graceful Deletion (< 5 minutes)
	if age < a.gracefulThreshold {
		analysis.Category = CategoryGracefulDeletion
		analysis.Action = ActionSkip
		analysis.Reason = fmt.Sprintf("Object marked for deletion %s ago (< %s); allowing native garbage collection and operator reconciliation to proceed",
			age.Round(time.Second), a.gracefulThreshold)
		return analysis
	}

	// Heuristic C: Storage Detach Stall (PVC with kubernetes.io/pvc-protection)
	if isPVC(gvr, kind) && hasFinalizer(finalizers, "kubernetes.io/pvc-protection") {
		pvName, _, _ := unstructured.NestedString(obj.Object, "spec", "volumeName")
		if pvName != "" {
			if vaErr, exists := vaErrors[pvName]; exists {
				analysis.Category = CategoryStorageDetach
				analysis.Action = ActionFlagStorageStall
				analysis.Reason = fmt.Sprintf("PVC stuck with pvc-protection finalizer; backing VolumeAttachment for PV %s reported stall: %s", pvName, vaErr)
				return analysis
			}
		}

		// PVC stuck with pvc-protection past threshold
		analysis.Category = CategoryStorageDetach
		analysis.Action = ActionFlagStorageStall
		analysis.Reason = fmt.Sprintf("PVC stuck with pvc-protection finalizer for %s (volume: %s); volume detach pending or pod unmount stalled",
			age.Round(time.Second), pvName)
		return analysis
	}

	// Heuristic B: Orphaned CRD (> 15 minutes, custom finalizer, operator missing or 0 replicas)
	if isCustomResource(gvr.Group) || hasCustomFinalizer(finalizers) {
		if age >= a.orphanedThreshold && len(finalizers) > 0 && !operatorWorkloadsPresent {
			analysis.Category = CategoryOrphanedCRD
			analysis.Action = ActionStripFinalizers
			analysis.Reason = fmt.Sprintf("Orphaned CRD instance stuck for %s (> %s) with finalizers %v; controlling operator is missing or scaled to 0 replicas",
				age.Round(time.Second), a.orphanedThreshold, finalizers)
			return analysis
		}
	}

	// Heuristic D: Deadlocked Child Resource (finalizers present past graceful threshold)
	if len(finalizers) > 0 {
		analysis.Category = CategoryDeadlockedChild
		analysis.Action = ActionStripFinalizers
		analysis.Reason = fmt.Sprintf("Deadlocked child resource stuck for %s with lingering finalizers %v",
			age.Round(time.Second), finalizers)
		return analysis
	}

	// Fallback: Lingering with no finalizers (e.g. controller syncing error)
	analysis.Category = CategoryDeadlockedChild
	analysis.Action = ActionInspect
	analysis.Reason = fmt.Sprintf("Object stuck in Terminating for %s with no finalizers present", age.Round(time.Second))
	return analysis
}

func (a *Analyzer) checkOperatorWorkloads(ctx context.Context, namespace string) (bool, error) {
	if a.client == nil {
		return false, nil
	}

	deployments, err := a.client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, d := range deployments.Items {
			if d.Status.ReadyReplicas > 0 {
				return true, nil
			}
		}
	}

	statefulsets, err := a.client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, s := range statefulsets.Items {
			if s.Status.ReadyReplicas > 0 {
				return true, nil
			}
		}
	}

	return false, nil
}

func (a *Analyzer) checkVolumeAttachmentErrors(ctx context.Context) map[string]string {
	res := make(map[string]string)
	if a.client == nil {
		return res
	}

	vaList, err := a.client.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		return res
	}

	for _, va := range vaList.Items {
		var pvName string
		if va.Spec.Source.PersistentVolumeName != nil {
			pvName = *va.Spec.Source.PersistentVolumeName
		}
		if pvName == "" {
			continue
		}

		if va.Status.DetachError != nil {
			res[pvName] = fmt.Sprintf("detach error: %s", va.Status.DetachError.Message)
		} else if va.Status.AttachError != nil {
			res[pvName] = fmt.Sprintf("attach error: %s", va.Status.AttachError.Message)
		} else if va.DeletionTimestamp != nil {
			res[pvName] = "volume attachment is stuck terminating"
		}
	}

	return res
}

func isPVC(gvr schema.GroupVersionResource, kind string) bool {
	return gvr.Resource == "persistentvolumeclaims" || strings.EqualFold(kind, "PersistentVolumeClaim")
}

func hasFinalizer(finalizers []string, target string) bool {
	for _, f := range finalizers {
		if f == target {
			return true
		}
	}
	return false
}

func hasCustomFinalizer(finalizers []string) bool {
	for _, f := range finalizers {
		// Ignore standard native kubernetes finalizers
		if f != "kubernetes" && f != "kubernetes.io/pvc-protection" && f != "kubernetes.io/pv-protection" {
			return true
		}
	}
	return false
}

func isCustomResource(group string) bool {
	if group == "" {
		return false
	}
	// Built-in standard groups
	standardGroups := map[string]bool{
		"apps":                     true,
		"batch":                    true,
		"core":                     true,
		"events.k8s.io":            true,
		"extensions":               true,
		"networking.k8s.io":        true,
		"policy":                   true,
		"rbac.authorization.k8s.io": true,
		"storage.k8s.io":           true,
		"coordination.k8s.io":      true,
		"admissionregistration.k8s.io": true,
		"apiregistration.k8s.io":   true,
	}
	return !standardGroups[group]
}
