package engine

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// DiagnosticCategory classifies why a resource is lingering in the terminating namespace.
type DiagnosticCategory string

const (
	CategoryGracefulDeletion DiagnosticCategory = "GracefulDeletion"
	CategoryOrphanedCRD      DiagnosticCategory = "OrphanedCRD"
	CategoryStorageDetach    DiagnosticCategory = "StorageDetachStall"
	CategoryDeadlockedChild  DiagnosticCategory = "DeadlockedChild"
	CategoryActiveResource   DiagnosticCategory = "ActiveResource"
)

// RemediationAction indicates the planned or executed remediation action.
type RemediationAction string

const (
	ActionSkip             RemediationAction = "SKIP"
	ActionStripFinalizers  RemediationAction = "STRIP_FINALIZERS"
	ActionFlagStorageStall RemediationAction = "FLAG_STORAGE_STALL"
	ActionInspect          RemediationAction = "INSPECT"
)

// ResourceAnalysis captures diagnostic heuristics for a single resource.
type ResourceAnalysis struct {
	GVR               schema.GroupVersionResource `json:"gvr"`
	Name              string                      `json:"name"`
	Namespace         string                      `json:"namespace"`
	Kind              string                      `json:"kind"`
	APIVersion        string                      `json:"apiVersion"`
	DeletionTimestamp *metav1.Time                `json:"deletionTimestamp,omitempty"`
	AgeSinceDeletion  time.Duration               `json:"ageSinceDeletion,omitempty"`
	Finalizers        []string                    `json:"finalizers"`
	Category          DiagnosticCategory          `json:"category"`
	Action            RemediationAction           `json:"action"`
	Reason            string                      `json:"reason"`
	RawObject         unstructured.Unstructured   `json:"-"`
}

// PatchResult records the outcome of dry-run validation and live patch operations.
type PatchResult struct {
	GVR       schema.GroupVersionResource `json:"gvr"`
	Namespace string                      `json:"namespace"`
	Name      string                      `json:"name"`
	DryRun    bool                        `json:"dryRun"`
	Success   bool                        `json:"success"`
	Message   string                      `json:"message"`
	Error     string                      `json:"error,omitempty"`
}
