package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/x7ssss/x7/pkg/remediation/k8s/admission"
	"github.com/x7ssss/x7/pkg/remediation/k8s/client"
	"github.com/x7ssss/x7/pkg/remediation/k8s/discovery"
	"github.com/x7ssss/x7/pkg/remediation/k8s/engine"
	"github.com/x7ssss/x7/pkg/remediation/k8s/gitops"
	"github.com/x7ssss/x7/pkg/remediation/k8s/locking"
	"github.com/x7ssss/x7/pkg/remediation/k8s/scanner"
	"github.com/x7ssss/x7/pkg/remediation/k8s/storage"
	"github.com/x7ssss/x7/pkg/ui"
)

var (
	k8sKubeconfigFlag string
	k8sTimeoutFlag    time.Duration
	k8sForceFlag      bool
	k8sDryRunFlag     bool
	k8sJSONFlag       bool
)

var k8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Diagnose and unstick terminating Kubernetes namespaces and CRDs",
	Long: `Diagnose and resolve deadlocked Kubernetes namespaces and resources.
Features 5-phase safe remediation: Lease locks, GitOps fencing, VAP disarming,
APIService triage, admission webhook neutralization, and surgical child finalizer stripping.`,
}

// K8sExecutionReport holds diagnostic and remediation outputs for k8s commands.
type K8sExecutionReport struct {
	Subcommand          string                                  `json:"subcommand"`
	ExecutionID         string                                  `json:"executionId,omitempty"`
	TargetNamespace     string                                  `json:"targetNamespace"`
	Mode                string                                  `json:"mode"`
	DryRun              bool                                    `json:"dryRun"`
	Force               bool                                    `json:"force"`
	Timestamp           string                                  `json:"timestamp"`
	LeaseHeld           bool                                    `json:"leaseHeld"`
	GitOpsCandidates    []gitops.GitOpsCandidate                `json:"gitOpsCandidates,omitempty"`
	GitOpsFenceResults  []gitops.GitOpsFenceResult              `json:"gitOpsFenceResults,omitempty"`
	VAPCandidates       []admission.VAPBindingCandidate         `json:"vapCandidates,omitempty"`
	VAPResults          []admission.VAPRemediationResult        `json:"vapResults,omitempty"`
	APIServices         []discovery.APIServiceIssue             `json:"apiServices,omitempty"`
	APIRemediations     []discovery.APIServiceRemediationResult `json:"apiRemediations,omitempty"`
	Webhooks            []admission.WebhookCandidate            `json:"webhooks,omitempty"`
	WebhookRemediations []admission.WebhookRemediationResult    `json:"webhookRemediations,omitempty"`
	DeadStorageNodes    []storage.DeadNodeStorageCandidate      `json:"deadStorageNodes,omitempty"`
	NodeTaintResults    []storage.NodeTaintResult               `json:"nodeTaintResults,omitempty"`
	ScanSummary         K8sScanSummaryStats                     `json:"scanSummary"`
	Analyses            []engine.ResourceAnalysis               `json:"analyses"`
	PatchResults        []engine.PatchResult                    `json:"patchResults,omitempty"`
	Summary             K8sReportSummary                        `json:"summary"`
}

type K8sScanSummaryStats struct {
	TotalResourcesFound int      `json:"totalResourcesFound"`
	DiscoveredGVRs      int      `json:"discoveredGVRs"`
	Warnings            []string `json:"warnings,omitempty"`
}

type K8sReportSummary struct {
	TotalFound           int `json:"totalFound"`
	GracefulSkipped      int `json:"gracefulSkipped"`
	OrphanedCRDs         int `json:"orphanedCRDs"`
	StorageStalls        int `json:"storageStalls"`
	DeadlockedChildren   int `json:"deadlockedChildren"`
	ActiveResources      int `json:"activeResources"`
	RemediatedFinalizers int `json:"remediatedFinalizers"`
}

var k8sDiagnoseCmd = &cobra.Command{
	Use:     "diagnose <namespace>",
	Aliases: []string{"analyze"},
	Short:   "Non-invasive diagnostic check across all resources & reconcilers",
	Long:    "Diagnose inspects lingering resources, GitOps reconcilers, VAPs, broken APIServices, and deadlocked webhooks in a namespace.",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nsName := args[0]

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		ctx, timeoutCancel := context.WithTimeout(ctx, k8sTimeoutFlag)
		defer timeoutCancel()

		clients, err := client.NewClients(k8sKubeconfigFlag)
		if err != nil {
			return fmt.Errorf("failed to initialize Kubernetes clients: %w", err)
		}

		ns, err := clients.KubeClient.CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("namespace %q does not exist", nsName)
			}
			return fmt.Errorf("failed to inspect namespace %q: %w", nsName, err)
		}

		isTerminating := ns.Status.Phase == corev1.NamespaceTerminating || ns.DeletionTimestamp != nil

		report := K8sExecutionReport{
			Subcommand:      "diagnose",
			TargetNamespace: nsName,
			Mode:            "NON-INVASIVE DIAGNOSTIC",
			DryRun:          true,
			Force:           false,
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
		}

		// 1. Scan namespace resources
		scannerInst := scanner.NewResourceScanner(clients.DiscoveryClient, clients.DynamicClient, scanner.DefaultListLimit)
		scanReport, err := scannerInst.ScanNamespace(ctx, nsName)
		if err != nil {
			return fmt.Errorf("scanner error: %w", err)
		}
		report.ScanSummary.TotalResourcesFound = scanReport.TotalFound
		report.ScanSummary.DiscoveredGVRs = len(scanReport.ScannedGVRs)
		report.ScanSummary.Warnings = scanReport.Warnings

		// 2. GitOps Diagnosis
		var rawItems []unstructured.Unstructured
		for _, res := range scanReport.Resources {
			rawItems = append(rawItems, res.Object)
		}
		nsLabels := make(map[string]string)
		if nsObj, err := clients.KubeClient.CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{}); err == nil {
			nsLabels = nsObj.Labels
		}

		gitOpsCandidates, _ := gitops.DiagnoseGitOps(ctx, clients.DynamicClient, nsName, nsLabels, rawItems)
		report.GitOpsCandidates = gitOpsCandidates

		// 3. VAP Diagnosis
		vapCandidates, _ := admission.DiagnoseVAP(ctx, clients.KubeClient, nsName)
		report.VAPCandidates = vapCandidates

		// 4. APIService Triage
		apiTriager := discovery.NewAPIServiceTriager(clients.DiscoveryClient, clients.AggregatorClient)
		apiIssues, _ := apiTriager.Diagnose(ctx, nsName)
		report.APIServices = apiIssues

		// 5. Webhook Neutralization
		webhookNeutralizer := admission.NewWebhookNeutralizer(clients.KubeClient)
		webhookCandidates, _ := webhookNeutralizer.Diagnose(ctx, nsName)
		report.Webhooks = webhookCandidates

		// 6. CSI Dead Node Storage Diagnosis
		storageCandidates, _ := storage.DiagnoseDeadStorageNodes(ctx, clients.KubeClient, nsName)
		report.DeadStorageNodes = storageCandidates

		// 7. Heuristic Analyzer
		analyzer := engine.NewAnalyzer(clients.KubeClient)
		analyses, err := analyzer.Analyze(ctx, nsName, scanReport.Resources)
		if err != nil {
			return fmt.Errorf("analyzer error: %w", err)
		}
		report.Analyses = analyses

		for _, a := range analyses {
			report.Summary.TotalFound++
			switch a.Category {
			case engine.CategoryGracefulDeletion:
				report.Summary.GracefulSkipped++
			case engine.CategoryOrphanedCRD:
				report.Summary.OrphanedCRDs++
			case engine.CategoryStorageDetach:
				report.Summary.StorageStalls++
			case engine.CategoryDeadlockedChild:
				report.Summary.DeadlockedChildren++
			case engine.CategoryActiveResource:
				report.Summary.ActiveResources++
			}
		}

		if k8sJSONFlag {
			return ui.PrintJSONStdout(report)
		}

		printK8sTerminalReport(report, isTerminating)
		return nil
	},
}

var k8sUnstickCmd = &cobra.Command{
	Use:     "unstick <namespace>",
	Aliases: []string{"heal", "plan", "recover"},
	Short:   "Execute 5-phase safe remediation sequence to unstick namespace",
	Long:    "Safely unblocks terminating namespace by fencing GitOps, disarming VAP, pruning dead APIServices, neutralizing webhooks, and stripping child finalizers.",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		nsName := args[0]

		dryRun := k8sDryRunFlag
		if !k8sForceFlag {
			dryRun = true
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		ctx, timeoutCancel := context.WithTimeout(ctx, k8sTimeoutFlag)
		defer timeoutCancel()

		clients, err := client.NewClients(k8sKubeconfigFlag)
		if err != nil {
			return fmt.Errorf("failed to initialize Kubernetes clients: %w", err)
		}

		ns, err := clients.KubeClient.CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("namespace %q does not exist", nsName)
			}
			return fmt.Errorf("failed to inspect namespace %q: %w", nsName, err)
		}

		isTerminating := ns.Status.Phase == corev1.NamespaceTerminating || ns.DeletionTimestamp != nil

		modeStr := "REMEDIATION DAG PLAN (DRY RUN)"
		if !dryRun {
			modeStr = "LIVE 5-PHASE REMEDIATION"
		}

		report := K8sExecutionReport{
			Subcommand:      "unstick",
			TargetNamespace: nsName,
			Mode:            modeStr,
			DryRun:          dryRun,
			Force:           k8sForceFlag,
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
		}

		// Phase 1: Acquire coordination.k8s.io Lease Lock
		leaseMgr := locking.NewLeaseManager(clients.KubeClient, locking.DefaultLeaseNamespace, locking.DefaultLeaseName, 60)
		if err := leaseMgr.Acquire(ctx); err != nil {
			return fmt.Errorf("Phase 1 Lease mutual exclusion failure: %w", err)
		}
		report.ExecutionID = leaseMgr.HolderIdentity()
		report.LeaseHeld = true
		defer func() {
			relCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = leaseMgr.Release(relCtx)
		}()

		// Scan resources
		scannerInst := scanner.NewResourceScanner(clients.DiscoveryClient, clients.DynamicClient, scanner.DefaultListLimit)
		scanReport, err := scannerInst.ScanNamespace(ctx, nsName)
		if err != nil {
			return fmt.Errorf("scanner error: %w", err)
		}
		report.ScanSummary.TotalResourcesFound = scanReport.TotalFound
		report.ScanSummary.DiscoveredGVRs = len(scanReport.ScannedGVRs)
		report.ScanSummary.Warnings = scanReport.Warnings

		var rawItems []unstructured.Unstructured
		for _, res := range scanReport.Resources {
			rawItems = append(rawItems, res.Object)
		}
		nsLabels := make(map[string]string)
		if nsObj, err := clients.KubeClient.CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{}); err == nil {
			nsLabels = nsObj.Labels
		}

		// Phase 2: Fence GitOps & Disarm VAP
		gitOpsCandidates, _ := gitops.DiagnoseGitOps(ctx, clients.DynamicClient, nsName, nsLabels, rawItems)
		report.GitOpsCandidates = gitOpsCandidates
		if len(gitOpsCandidates) > 0 {
			fenceResults, _ := gitops.FenceNamespaceGitOps(ctx, clients.DynamicClient, gitOpsCandidates, dryRun)
			report.GitOpsFenceResults = fenceResults
		}

		vapCandidates, _ := admission.DiagnoseVAP(ctx, clients.KubeClient, nsName)
		report.VAPCandidates = vapCandidates
		if len(vapCandidates) > 0 {
			vapResults, _ := admission.DisarmVAPBindings(ctx, clients.KubeClient, vapCandidates, dryRun)
			report.VAPResults = vapResults
		}

		// Phase 3: Triage and delete broken APIServices
		apiTriager := discovery.NewAPIServiceTriager(clients.DiscoveryClient, clients.AggregatorClient)
		apiIssues, _ := apiTriager.Diagnose(ctx, nsName)
		report.APIServices = apiIssues
		if len(apiIssues) > 0 {
			apiRemediations, _ := apiTriager.Remediate(ctx, apiIssues, dryRun)
			report.APIRemediations = apiRemediations
		}

		// Phase 4: Temporarily downgrade blocking webhooks to failurePolicy=Ignore
		webhookNeutralizer := admission.NewWebhookNeutralizer(clients.KubeClient)
		webhookCandidates, _ := webhookNeutralizer.Diagnose(ctx, nsName)
		report.Webhooks = webhookCandidates
		if len(webhookCandidates) > 0 {
			webhookRemediations, _ := webhookNeutralizer.Remediate(ctx, webhookCandidates, dryRun)
			report.WebhookRemediations = webhookRemediations
		}

		// Phase 5: Storage Node Taints and Surgical Child Finalizer Stripping
		storageCandidates, _ := storage.DiagnoseDeadStorageNodes(ctx, clients.KubeClient, nsName)
		report.DeadStorageNodes = storageCandidates
		if len(storageCandidates) > 0 {
			nodeTaintResults, _ := storage.ApplyOutOfServiceTaints(ctx, clients.KubeClient, storageCandidates, dryRun)
			report.NodeTaintResults = nodeTaintResults
		}

		analyzer := engine.NewAnalyzer(clients.KubeClient)
		analyses, err := analyzer.Analyze(ctx, nsName, scanReport.Resources)
		if err != nil {
			return fmt.Errorf("analyzer error: %w", err)
		}
		report.Analyses = analyses

		for _, a := range analyses {
			report.Summary.TotalFound++
			switch a.Category {
			case engine.CategoryGracefulDeletion:
				report.Summary.GracefulSkipped++
			case engine.CategoryOrphanedCRD:
				report.Summary.OrphanedCRDs++
			case engine.CategoryStorageDetach:
				report.Summary.StorageStalls++
			case engine.CategoryDeadlockedChild:
				report.Summary.DeadlockedChildren++
			case engine.CategoryActiveResource:
				report.Summary.ActiveResources++
			}
		}

		patcher := engine.NewFinalizerPatcher(clients.DynamicClient)
		for _, a := range analyses {
			if a.Action == engine.ActionStripFinalizers {
				patchRes, err := patcher.StripFinalizers(ctx, a, dryRun)
				if err != nil {
					if patchRes != nil {
						report.PatchResults = append(report.PatchResults, *patchRes)
					} else {
						report.PatchResults = append(report.PatchResults, engine.PatchResult{
							GVR:       a.GVR,
							Namespace: a.Namespace,
							Name:      a.Name,
							DryRun:    dryRun,
							Success:   false,
							Error:     err.Error(),
						})
					}
				} else {
					report.PatchResults = append(report.PatchResults, *patchRes)
					if patchRes.Success {
						report.Summary.RemediatedFinalizers++
					}
				}
			}
		}

		if k8sJSONFlag {
			return ui.PrintJSONStdout(report)
		}

		printK8sTerminalReport(report, isTerminating)
		return nil
	},
}

func printK8sTerminalReport(report K8sExecutionReport, isTerminating bool) {
	fmt.Printf("\n================================================================================\n")
	fmt.Printf("                   x7 k8s: Namespace Deadlock Resolver                          \n")
	fmt.Printf("================================================================================\n")
	fmt.Printf("  Command          : %s\n", strings.ToUpper(report.Subcommand))
	fmt.Printf("  Target Namespace : %s\n", report.TargetNamespace)
	fmt.Printf("  Mode             : %s\n", report.Mode)
	if report.ExecutionID != "" {
		fmt.Printf("  Execution ID     : %s\n", report.ExecutionID)
		fmt.Printf("  Lease Lock       : coordination.k8s.io/v1 acquired in kube-system\n")
	}
	if !isTerminating {
		fmt.Printf("  Namespace Status : Active (Note: Not currently marked for deletion)\n")
	} else {
		fmt.Printf("  Namespace Status : Terminating (Deletion in progress)\n")
	}
	fmt.Printf("--------------------------------------------------------------------------------\n\n")

	// Phase 2 Results: GitOps & VAP
	fmt.Printf("[Phase 2] GitOps Controller Fencing & VAP Disarmer:\n")
	if len(report.GitOpsCandidates) == 0 {
		fmt.Println("   [PASS] No GitOps reconcilers (ArgoCD/Flux) detected.")
	} else {
		for _, c := range report.GitOpsCandidates {
			fmt.Printf("   [FENCE] %s reconciler found: %s/%s (via %s)\n", c.Type, c.Namespace, c.Name, c.SourceLabel)
		}
		for _, res := range report.GitOpsFenceResults {
			prefix := "[PLAN]"
			if !res.DryRun {
				prefix = "[EXECUTED]"
			}
			fmt.Printf("   %s %s\n", prefix, res.Message)
		}
	}

	if len(report.VAPCandidates) == 0 {
		fmt.Println("   [PASS] No blocking ValidatingAdmissionPolicyBindings detected.")
	} else {
		for _, v := range report.VAPCandidates {
			fmt.Printf("   [WARN] VAP binding %s references %s with parameterNotFoundAction=Deny\n",
				v.BindingName, v.ParamRefNamespace)
		}
		for _, res := range report.VAPResults {
			prefix := "[PLAN]"
			if !res.DryRun {
				prefix = "[EXECUTED]"
			}
			fmt.Printf("   %s %s\n", prefix, res.Message)
		}
	}
	fmt.Println()

	// Phase 3 Results: APIService Triage
	fmt.Printf("[Phase 3] Extension APIService Triage:\n")
	if len(report.APIServices) == 0 {
		fmt.Println("   [PASS] No dead or unresolvable APIServices detected.")
	} else {
		for _, issue := range report.APIServices {
			fmt.Printf("   [FAIL] Dead APIService: %s (Group: %s/%s, Reason: %s)\n",
				issue.Name, issue.Group, issue.Version, issue.Reason)
		}
		for _, res := range report.APIRemediations {
			prefix := "[PLAN]"
			if !res.DryRun {
				prefix = "[EXECUTED]"
			}
			fmt.Printf("   %s %s\n", prefix, res.Message)
		}
	}
	fmt.Println()

	// Phase 4 Results: Admission Webhook Neutralization
	fmt.Printf("[Phase 4] Admission Webhook Neutralization:\n")
	if len(report.Webhooks) == 0 {
		fmt.Println("   [PASS] No blocking webhooks pointing to terminating namespace.")
	} else {
		for _, wh := range report.Webhooks {
			fmt.Printf("   [WARN] Webhook %s in %s %s has failurePolicy=Fail\n",
				wh.WebhookName, wh.Kind, wh.ConfigName)
		}
		for _, res := range report.WebhookRemediations {
			prefix := "[PLAN]"
			if !res.DryRun {
				prefix = "[EXECUTED]"
			}
			fmt.Printf("   %s %s\n", prefix, res.Message)
		}
	}
	fmt.Println()

	// Phase 5 Results: Storage Node Taints & Finalizer Stripping
	fmt.Printf("[Phase 5] CSI Storage Node Taints & Child Finalizer Stripping:\n")
	if len(report.DeadStorageNodes) == 0 {
		fmt.Println("   [PASS] No dead nodes hosting stuck PVC pods detected.")
	} else {
		for _, sn := range report.DeadStorageNodes {
			fmt.Printf("   [STORAGE] Dead node %s (%s) hosts terminating pod %s with PVC %s\n",
				sn.NodeName, sn.NodeCondition, sn.PodName, sn.PVCName)
		}
		for _, res := range report.NodeTaintResults {
			prefix := "[PLAN]"
			if !res.DryRun {
				prefix = "[EXECUTED]"
			}
			fmt.Printf("   %s %s\n", prefix, res.Message)
		}
	}

	if len(report.Analyses) == 0 {
		fmt.Println("   [EMPTY] No lingering objects found in namespace.")
	} else {
		fmt.Printf("\n   --- Diagnostic Tree (%d objects across %d GVRs) ---\n",
			report.ScanSummary.TotalResourcesFound, report.ScanSummary.DiscoveredGVRs)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "   RESOURCE\tNAME\tCATEGORY\tACTION\tDETAILS\n")
		fmt.Fprintf(w, "   --------\t----\t--------\t------\t-------\n")
		for _, a := range report.Analyses {
			details := a.Reason
			if len(a.Finalizers) > 0 {
				details = fmt.Sprintf("Finalizers: %v | %s", a.Finalizers, a.Reason)
			}
			fmt.Fprintf(w, "   %s\t%s\t%s\t%s\t%s\n",
				a.GVR.Resource, a.Name, a.Category, a.Action, truncateString(details, 60))
		}
		_ = w.Flush()
	}

	if len(report.PatchResults) > 0 {
		fmt.Printf("\n   --- Finalizer Stripping Operations ---\n")
		for _, pr := range report.PatchResults {
			status := "[PASS]"
			if !pr.Success {
				status = "[FAIL]"
			}
			fmt.Printf("   %s %s/%s (%s): %s\n",
				status, pr.Namespace, pr.Name, pr.GVR.Resource, pr.Message)
		}
	}
	fmt.Println()

	// Summary
	fmt.Printf("================================================================================\n")
	fmt.Printf("                                Execution Summary                               \n")
	fmt.Printf("================================================================================\n")
	fmt.Printf("  Total Lingering Objects   : %d\n", report.Summary.TotalFound)
	fmt.Printf("  Graceful Deletion (Skip)  : %d (< 5m age)\n", report.Summary.GracefulSkipped)
	fmt.Printf("  Orphaned CRDs             : %d (> 15m age, dead operator)\n", report.Summary.OrphanedCRDs)
	fmt.Printf("  Storage Detach Stalls     : %d (stuck PVCs)\n", report.Summary.StorageStalls)
	fmt.Printf("  Deadlocked Child Objects  : %d (blocking namespace completion)\n", report.Summary.DeadlockedChildren)
	fmt.Printf("  Finalizer Strips Executed : %d\n", report.Summary.RemediatedFinalizers)
	fmt.Printf("--------------------------------------------------------------------------------\n")

	if report.Subcommand == "diagnose" {
		fmt.Printf("\n>>> DIAGNOSTIC COMPLETE. Run 'x7 k8s unstick %s --dry-run' to preview remediation plan.\n\n", report.TargetNamespace)
	} else if report.DryRun {
		fmt.Printf("\n>>> REMEDIATION READY. Run 'x7 k8s unstick %s --force' to execute live remediation.\n\n", report.TargetNamespace)
	} else {
		fmt.Printf("\n>>> HEALING COMPLETE. Child blockers resolved. The Kubernetes namespace controller\n")
		fmt.Printf("    will now drop the 'kubernetes' finalizer and purge %s cleanly.\n\n", report.TargetNamespace)
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return strings.TrimSpace(s[:maxLen-3]) + "..."
}

func init() {
	pf := k8sCmd.PersistentFlags()
	pf.StringVar(&k8sKubeconfigFlag, "kubeconfig", "", "Path to kubeconfig")
	pf.DurationVar(&k8sTimeoutFlag, "timeout", 10*time.Minute, "Operation timeout")
	pf.BoolVar(&k8sDryRunFlag, "dry-run", true, "Preview operations safely without mutating resources")
	pf.BoolVar(&k8sJSONFlag, "json", false, "Output machine-readable JSON for CI/CD automation")

	k8sUnstickCmd.Flags().BoolVarP(&k8sForceFlag, "force", "f", false, "Execute mutations (bypass dry-run)")

	k8sCmd.AddCommand(k8sDiagnoseCmd)
	k8sCmd.AddCommand(k8sUnstickCmd)

	RootCmd.AddCommand(k8sCmd)
}
