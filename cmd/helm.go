package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/x7ssss/x7/pkg/remediation/helm/codec"
	"github.com/x7ssss/x7/pkg/remediation/helm/k8s"
	"github.com/x7ssss/x7/pkg/ui"
)

var (
	helmNamespaceFlag  string
	helmKubeconfigFlag string
	helmContextFlag    string
	helmStaleAfterFlag time.Duration
	helmStrategyFlag   string
	helmForceFlag      bool
	helmDryRunFlag     bool
	helmJSONFlag       bool
)

var helmCmd = &cobra.Command{
	Use:   "helm",
	Short: "Inspect and recover deadlocked Helm v3 releases",
	Long: `Inspect and unlock deadlocked Helm v3 releases (pending-upgrade, pending-install, pending-rollback)
without the Helm SDK. Performs atomic dual-mutations on Kubernetes secrets with distributed lease locks.`,
}

// HelmInspectReport holds machine-readable JSON output for helm inspect.
type HelmInspectReport struct {
	ReleaseName       string  `json:"releaseName"`
	Namespace         string  `json:"namespace"`
	Revision          int     `json:"revision"`
	SecretName        string  `json:"secretName"`
	SecretLabelStatus string  `json:"secretLabelStatus"`
	PayloadStatus     string  `json:"payloadStatus"`
	Desync            bool    `json:"desync"`
	LastModified      string  `json:"lastModified"`
	AgeSeconds        float64 `json:"ageSeconds"`
	StaleThreshold    string  `json:"staleThreshold"`
	IsStuck           bool    `json:"isStuck"`
	IsStale           bool    `json:"isStale"`
	LeaseHeld         bool    `json:"leaseHeld"`
	LeaseHolder       string  `json:"leaseHolder,omitempty"`
	Verdict           string  `json:"verdict"`
	Recommendation    string  `json:"recommendation"`
	DryRun            bool    `json:"dryRun"`
}

// HelmRecoverReport holds machine-readable JSON output for helm recover.
type HelmRecoverReport struct {
	ReleaseName    string `json:"releaseName"`
	Namespace      string `json:"namespace"`
	Revision       int    `json:"revision"`
	TargetSecret   string `json:"targetSecret"`
	Strategy       string `json:"strategy"`
	PreviousStatus string `json:"previousStatus"`
	NewStatus      string `json:"newStatus"`
	DryRun         bool   `json:"dryRun"`
	Success        bool   `json:"success"`
	Message        string `json:"message"`
}

var helmInspectCmd = &cobra.Command{
	Use:     "inspect <release>",
	Aliases: []string{"analyze", "status"},
	Short:   "Perform read-only diagnostic audit of a Helm release",
	Long:    "Inspect audit-checks the Kubernetes storage secret, payload JSON, and lease lock for a Helm release.",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		releaseName := args[0]
		ctx := context.Background()

		client, defaultNS, err := k8s.NewClient(k8s.ClientConfig{
			KubeconfigPath: helmKubeconfigFlag,
			ContextName:    helmContextFlag,
		})
		if err != nil {
			return fmt.Errorf("kubernetes client init failed: %w", err)
		}

		targetNS := helmNamespaceFlag
		if targetNS == "" {
			targetNS = defaultNS
		}

		detail, err := k8s.GetLatestReleaseSecret(ctx, client, targetNS, releaseName)
		if err != nil {
			return fmt.Errorf("failed to fetch release secret: %w", err)
		}

		leaseStatus, err := k8s.CheckLease(ctx, client, targetNS, releaseName)
		if err != nil {
			return fmt.Errorf("failed to inspect lease lock: %w", err)
		}

		now := time.Now().UTC()
		var age time.Duration
		ageStr := "unknown"
		if !detail.ModifiedAt.IsZero() {
			age = now.Sub(detail.ModifiedAt).Round(time.Second)
			ageStr = fmt.Sprintf("%s ago (%s)", age.String(), detail.ModifiedAt.Format(time.RFC3339))
		}

		isStuck := codec.IsPending(detail.Status)
		if !isStuck && detail.Payload.Info != nil {
			isStuck = codec.IsPending(detail.Payload.Info.Status)
		}

		isStale := isStuck && age > helmStaleAfterFlag

		payloadStatus := "unknown"
		if detail.Payload.Info != nil {
			payloadStatus = detail.Payload.Info.Status
		}
		desync := detail.Status != payloadStatus

		leaseInfo := "None (Unlocked)"
		if leaseStatus.Exists {
			if leaseStatus.IsHeld {
				leaseInfo = fmt.Sprintf("LOCKED by %s (expires in %s)", leaseStatus.Holder, leaseStatus.ExpiresIn.Round(time.Second))
			} else {
				leaseInfo = fmt.Sprintf("Expired (last held by %s)", leaseStatus.Holder)
			}
		}

		verdict := "HEALTHY"
		recommendation := "No remediation required. Release is in an operable state."

		if isStuck {
			if isStale {
				verdict = "DEADLOCKED (Pending operation abandoned)"
				if detail.Revision == 1 && (detail.Status == codec.StatusPendingInstall || payloadStatus == codec.StatusPendingInstall) {
					recommendation = fmt.Sprintf("Run: x7 helm recover %s -n %s --strategy=mark-failed (recommended) OR --strategy=purge-v1", releaseName, targetNS)
				} else {
					recommendation = fmt.Sprintf("Run: x7 helm recover %s -n %s", releaseName, targetNS)
				}
			} else {
				verdict = "PENDING (Active run or recent mutation)"
				recommendation = fmt.Sprintf("Release modified %s ago (< %s threshold). Wait for completion or use --force to override.", age.String(), helmStaleAfterFlag.String())
			}
		}

		if helmJSONFlag {
			report := HelmInspectReport{
				ReleaseName:       detail.Name,
				Namespace:         detail.Namespace,
				Revision:          detail.Revision,
				SecretName:        detail.SecretName,
				SecretLabelStatus: detail.Status,
				PayloadStatus:     payloadStatus,
				Desync:            desync,
				LastModified:      ageStr,
				AgeSeconds:        age.Seconds(),
				StaleThreshold:    helmStaleAfterFlag.String(),
				IsStuck:           isStuck,
				IsStale:           isStale,
				LeaseHeld:         leaseStatus.Exists && leaseStatus.IsHeld,
				LeaseHolder:       leaseStatus.Holder,
				Verdict:           verdict,
				Recommendation:    recommendation,
				DryRun:            helmDryRunFlag,
			}
			return ui.PrintJSONStdout(report)
		}

		desyncNotice := "Synchronized"
		if desync {
			desyncNotice = fmt.Sprintf("DESYNCHRONIZED (Secret label: %s, Payload JSON: %s)", detail.Status, payloadStatus)
		}

		entries := [][2]string{
			{"Release Name", detail.Name},
			{"Namespace", detail.Namespace},
			{"Latest Revision", fmt.Sprintf("v%d", detail.Revision)},
			{"Secret Name", detail.SecretName},
			{"Secret Label Status", detail.Status},
			{"Payload Status", payloadStatus},
			{"State Alignment", desyncNotice},
			{"Last Modified", ageStr},
			{"Stale Threshold", helmStaleAfterFlag.String()},
			{"Distributed Lock", leaseInfo},
			{"Verdict", verdict},
			{"Recommended Action", recommendation},
		}

		ui.RenderKeyValueBlock(os.Stdout, fmt.Sprintf("Helm Release Audit: %s (v%d)", releaseName, detail.Revision), entries)
		return nil
	},
}

var helmRecoverCmd = &cobra.Command{
	Use:     "recover <release>",
	Aliases: []string{"heal", "unlock"},
	Short:   "Surgically unlock a deadlocked Helm v3 release",
	Long:    "Safely clears deadlock states (pending-upgrade, pending-install, pending-rollback) using dual atomic mutations.",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		releaseName := args[0]
		ctx := context.Background()

		client, defaultNS, err := k8s.NewClient(k8s.ClientConfig{
			KubeconfigPath: helmKubeconfigFlag,
			ContextName:    helmContextFlag,
		})
		if err != nil {
			return fmt.Errorf("kubernetes client init failed: %w", err)
		}

		targetNS := helmNamespaceFlag
		if targetNS == "" {
			targetNS = defaultNS
		}

		strategy := strings.ToLower(strings.TrimSpace(helmStrategyFlag))
		if strategy != "mark-failed" && strategy != "purge-v1" {
			return fmt.Errorf("invalid strategy %q: must be 'mark-failed' or 'purge-v1'", helmStrategyFlag)
		}

		// 1. Fetch release secret
		detail, err := k8s.GetLatestReleaseSecret(ctx, client, targetNS, releaseName)
		if err != nil {
			return fmt.Errorf("failed to fetch release secret: %w", err)
		}

		// 2. Validate current status
		payloadStatus := ""
		if detail.Payload.Info != nil {
			payloadStatus = detail.Payload.Info.Status
		}

		isStuck := codec.IsPending(detail.Status) || codec.IsPending(payloadStatus)
		if !isStuck {
			if helmJSONFlag {
				return ui.PrintJSONStdout(HelmRecoverReport{
					ReleaseName:    releaseName,
					Namespace:      targetNS,
					Revision:       detail.Revision,
					TargetSecret:   detail.SecretName,
					Strategy:       strategy,
					PreviousStatus: detail.Status,
					NewStatus:      detail.Status,
					DryRun:         helmDryRunFlag,
					Success:        true,
					Message:        "Release is not in a pending state; no deadlock detected",
				})
			}
			fmt.Fprintf(os.Stdout, "Release %q in namespace %q is in state %q (not pending). No deadlock detected. Exiting.\n", releaseName, targetNS, detail.Status)
			return nil
		}

		// 3. Stale Heuristic check
		now := time.Now().UTC()
		var age time.Duration
		if !detail.ModifiedAt.IsZero() {
			age = now.Sub(detail.ModifiedAt)
			if age < helmStaleAfterFlag && !helmForceFlag {
				return fmt.Errorf("aborting: release %q was modified %s ago (less than stale threshold %s). Use --force to override",
					releaseName, age.Round(time.Second).String(), helmStaleAfterFlag.String())
			}
		}

		// 4. Validate strategy for revision
		if strategy == "purge-v1" && detail.Revision != 1 {
			return fmt.Errorf("strategy 'purge-v1' is only valid for revision 1; current revision is v%d (use 'mark-failed')", detail.Revision)
		}

		if helmDryRunFlag {
			if helmJSONFlag {
				return ui.PrintJSONStdout(HelmRecoverReport{
					ReleaseName:    releaseName,
					Namespace:      targetNS,
					Revision:       detail.Revision,
					TargetSecret:   detail.SecretName,
					Strategy:       strategy,
					PreviousStatus: detail.Status,
					NewStatus:      codec.StatusFailed,
					DryRun:         true,
					Success:        true,
					Message:        fmt.Sprintf("Dry-run preview: would apply %s to release secret %s", strategy, detail.SecretName),
				})
			}
			fmt.Fprintln(os.Stdout, "[DRY-RUN] Execution plan simulated:")
			fmt.Fprintf(os.Stdout, "[DRY-RUN] Target Secret: %s (Namespace: %s)\n", detail.SecretName, targetNS)
			fmt.Fprintf(os.Stdout, "[DRY-RUN] Current Status: %s (Revision: v%d, Age: %s)\n", detail.Status, detail.Revision, age.Round(time.Second).String())
			fmt.Fprintf(os.Stdout, "[DRY-RUN] Strategy: %s\n", strategy)
			if strategy == "purge-v1" {
				fmt.Fprintln(os.Stdout, "[DRY-RUN] Action: DELETE Secret sh.helm.release.v1."+releaseName+".v1")
			} else {
				fmt.Fprintln(os.Stdout, "[DRY-RUN] Action: ATOMIC PATCH Secret labels (status=failed) and release JSON (.info.status=failed)")
			}
			return nil
		}

		// 5. Distributed Mutual Exclusion: acquire Lease lock
		if !helmJSONFlag {
			fmt.Fprintf(os.Stdout, "Acquiring distributed lease lock 'helm-lock-%s'...\n", releaseName)
		}
		leaseLock, err := k8s.AcquireLease(ctx, client, targetNS, releaseName, "")
		if err != nil {
			return fmt.Errorf("failed to acquire distributed mutual exclusion lease: %w", err)
		}
		defer func() {
			if relErr := leaseLock.Release(ctx); relErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to cleanly delete lease lock: %v\n", relErr)
			}
		}()

		// 6. Execute Healing
		if strategy == "purge-v1" {
			if err := k8s.PurgeReleaseSecret(ctx, client, targetNS, detail.SecretName, false); err != nil {
				return fmt.Errorf("failed to purge release secret %s: %w", detail.SecretName, err)
			}
			if helmJSONFlag {
				return ui.PrintJSONStdout(HelmRecoverReport{
					ReleaseName:    releaseName,
					Namespace:      targetNS,
					Revision:       1,
					TargetSecret:   detail.SecretName,
					Strategy:       "purge-v1",
					PreviousStatus: detail.Status,
					NewStatus:      "PURGED",
					DryRun:         false,
					Success:        true,
					Message:        "Revision 1 secret deleted successfully",
				})
			}
			entries := [][2]string{
				{"Action", "PURGED REVISION 1 SECRET"},
				{"Release", releaseName},
				{"Namespace", targetNS},
				{"Deleted Secret", detail.SecretName},
				{"Next Step", fmt.Sprintf("Run 'helm install %s <chart>' to create clean revision 1", releaseName)},
			}
			ui.RenderKeyValueBlock(os.Stdout, "Release Unlocked: Purge v1", entries)
			return nil
		}

		unlockMsg := "Release unlocked by x7 helm recover"
		updatedSecret, err := k8s.AtomicPatchRelease(ctx, client, detail, codec.StatusFailed, unlockMsg, false)
		if err != nil {
			return fmt.Errorf("failed to execute atomic dual-mutation patch: %w", err)
		}

		if helmJSONFlag {
			return ui.PrintJSONStdout(HelmRecoverReport{
				ReleaseName:    releaseName,
				Namespace:      targetNS,
				Revision:       detail.Revision,
				TargetSecret:   updatedSecret.Name,
				Strategy:       "mark-failed",
				PreviousStatus: detail.Status,
				NewStatus:      codec.StatusFailed,
				DryRun:         false,
				Success:        true,
				Message:        "Atomic dual-mutation applied successfully; release marked failed",
			})
		}

		entries := [][2]string{
			{"Action", "ATOMIC DUAL-MUTATION UNLOCK"},
			{"Release", releaseName},
			{"Namespace", targetNS},
			{"Revision", fmt.Sprintf("v%d", detail.Revision)},
			{"Secret Patched", updatedSecret.Name},
			{"Previous Status", detail.Status},
			{"New Status", codec.StatusFailed},
			{"Labels Modified", "status=failed, modifiedAt=now"},
			{"Payload Modified", ".info.status=failed, .info.description=" + unlockMsg},
			{"Next Step", fmt.Sprintf("Run 'helm upgrade --install %s <chart>' to perform 3-way merge upgrade", releaseName)},
		}
		ui.RenderKeyValueBlock(os.Stdout, "Release Successfully Recovered", entries)
		return nil
	},
}

func init() {
	pf := helmCmd.PersistentFlags()
	pf.StringVarP(&helmNamespaceFlag, "namespace", "n", "", "Kubernetes namespace scope")
	pf.StringVarP(&helmKubeconfigFlag, "kubeconfig", "k", "", "Path to the kubeconfig file")
	pf.StringVarP(&helmContextFlag, "context", "c", "", "Kubernetes context to use")
	pf.DurationVar(&helmStaleAfterFlag, "stale-after", 10*time.Minute, "Staleness threshold before pending release is deemed abandoned")
	pf.BoolVar(&helmDryRunFlag, "dry-run", false, "Simulate operations without modifying cluster state")
	pf.BoolVar(&helmJSONFlag, "json", false, "Output machine-readable JSON for CI/CD automation")

	helmRecoverCmd.Flags().StringVar(&helmStrategyFlag, "strategy", "mark-failed", "Unlock strategy: 'mark-failed' (recommended) or 'purge-v1' (revision 1 only)")
	helmRecoverCmd.Flags().BoolVarP(&helmForceFlag, "force", "f", false, "Force unlock even if the release was modified within stale threshold")

	helmCmd.AddCommand(helmInspectCmd)
	helmCmd.AddCommand(helmRecoverCmd)

	RootCmd.AddCommand(helmCmd)
}
