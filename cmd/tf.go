package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/x7ssss/x7/pkg/remediation/terraform/backend"
	"github.com/x7ssss/x7/pkg/remediation/terraform/detector"
	"github.com/x7ssss/x7/pkg/remediation/terraform/ghrun"
	"github.com/x7ssss/x7/pkg/remediation/terraform/safety"
	tfui "github.com/x7ssss/x7/pkg/remediation/terraform/ui"
	"github.com/x7ssss/x7/pkg/ui"
)

var (
	tfStatePathFlag     string
	tfBackendTypeFlag   string
	tfTableNameFlag     string
	tfS3BucketFlag      string
	tfS3KeyFlag         string
	tfLockIDFlag        string
	tfStaleAfterFlag    time.Duration
	tfForceFlag         bool
	tfYesFlag           bool
	tfDryRunFlag        bool
	tfJSONFlag          bool
	tfGitHubTokenFlag   string
	tfGitHubRepoFlag    string
	tfGitHubRunIDFlag   string
	tfGitHubAPIURLFlag  string
)

var tfCmd = &cobra.Command{
	Use:   "tf",
	Short: "Inspect and unlock remote Terraform and OpenTofu state locks",
	Long: `Inspect, diagnose, and safely break remote state locks across AWS S3/DynamoDB,
S3 Native object locks, Azure Blob Storage, and PostgreSQL backends.`,
}

// TFInspectReport holds machine-readable JSON output for tf inspect.
type TFInspectReport struct {
	Status      string            `json:"status"`
	BackendType string            `json:"backendType"`
	Target      string            `json:"target"`
	IsStale     bool              `json:"isStale"`
	AgeSeconds  float64           `json:"ageSeconds"`
	StaleAfter  string            `json:"staleAfter"`
	DryRun      bool              `json:"dryRun"`
	Lock        *backend.LockInfo `json:"lock,omitempty"`
}

// TFUnlockReport holds machine-readable JSON output for tf unlock.
type TFUnlockReport struct {
	Status  string            `json:"status"`
	LockID  string            `json:"lockId"`
	Backend string            `json:"backend"`
	Target  string            `json:"target"`
	DryRun  bool              `json:"dryRun"`
	Force   bool              `json:"force"`
	Lock    *backend.LockInfo `json:"lock,omitempty"`
}

var tfInspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect remote state lock without modifying remote state",
	Long:  "Inspect checks the remote backend for any active or stale locks and outputs diagnostics in brutalist table or JSON.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		mgr, err := loadTFManager()
		if err != nil {
			return fmt.Errorf("terraform backend detection failed: %w", err)
		}

		lock, err := mgr.Inspect(ctx)
		if err != nil {
			return fmt.Errorf("lock inspection failed for %s: %w", mgr.Target(), err)
		}

		if tfJSONFlag {
			report := TFInspectReport{
				BackendType: mgr.Type(),
				Target:      mgr.Target(),
				StaleAfter:  tfStaleAfterFlag.String(),
				DryRun:      tfDryRunFlag,
			}
			if lock == nil {
				report.Status = "CLEAN"
			} else {
				report.Lock = lock
				report.IsStale = lock.IsStale(tfStaleAfterFlag)
				report.AgeSeconds = lock.Age().Seconds()
				if report.IsStale {
					report.Status = "LOCKED_STALE"
				} else {
					report.Status = "LOCKED_ACTIVE"
				}
			}
			return ui.PrintJSONStdout(report)
		}

		if lock == nil {
			tfui.RenderClean(os.Stdout, mgr.Type(), mgr.Target())
			return nil
		}

		tfui.RenderLockInfo(os.Stdout, lock, tfStaleAfterFlag)
		return nil
	},
}

var tfUnlockCmd = &cobra.Command{
	Use:     "unlock",
	Aliases: []string{"break"},
	Short:   "Safely break a remote state lock with staleness gates and confirmation",
	Long:    "Unlock verifies lock staleness, matches lock ID, prompts for confirmation, and releases the remote state lock.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		mgr, err := loadTFManager()
		if err != nil {
			return fmt.Errorf("terraform backend detection failed: %w", err)
		}

		lock, err := mgr.Inspect(ctx)
		if err != nil {
			return fmt.Errorf("lock inspection failed for %s: %w", mgr.Target(), err)
		}

		if lock == nil {
			if tfJSONFlag {
				return ui.PrintJSONStdout(TFUnlockReport{
					Status:  "NO_LOCK",
					Backend: mgr.Type(),
					Target:  mgr.Target(),
					DryRun:  tfDryRunFlag,
				})
			}
			tfui.RenderClean(os.Stdout, mgr.Type(), mgr.Target())
			fmt.Println("No active lock found. Nothing to break.")
			return nil
		}

		if !tfJSONFlag {
			tfui.RenderLockInfo(os.Stdout, lock, tfStaleAfterFlag)
		}

		// 1. Verify lock ID match if specified
		if err := safety.VerifyLockID(lock, tfLockIDFlag); err != nil {
			return err
		}

		// 2. Staleness verification gate
		if err := safety.VerifyStaleness(lock, tfStaleAfterFlag, tfForceFlag); err != nil {
			return err
		}

		// 3. Runner termination gate
		if err := verifyTFRunner(ctx, tfForceFlag); err != nil {
			return err
		}

		if tfDryRunFlag {
			if tfJSONFlag {
				return ui.PrintJSONStdout(TFUnlockReport{
					Status:  "DRY_RUN_PASSED",
					LockID:  lock.ID,
					Backend: mgr.Type(),
					Target:  mgr.Target(),
					DryRun:  true,
					Force:   tfForceFlag,
					Lock:    lock,
				})
			}
			fmt.Fprintf(os.Stdout, "[dry-run] all safety checks passed; would break lock %s on %s\n", lock.ID, mgr.Target())
			return nil
		}

		// 4. Double-check confirmation
		nonInteractive := !safety.IsTerminal(os.Stdin) || tfYesFlag || tfJSONFlag
		confirmed, err := safety.ConfirmBreak(os.Stdin, os.Stdout, lock.ID, tfForceFlag, nonInteractive)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("aborted by user: lock release cancelled")
		}

		// 5. Execute lock release
		if err := mgr.Break(ctx, lock.ID, tfForceFlag); err != nil {
			return fmt.Errorf("failed to break lock %s: %w", lock.ID, err)
		}

		if tfJSONFlag {
			return ui.PrintJSONStdout(TFUnlockReport{
				Status:  "UNLOCKED",
				LockID:  lock.ID,
				Backend: mgr.Type(),
				Target:  mgr.Target(),
				DryRun:  false,
				Force:   tfForceFlag,
				Lock:    lock,
			})
		}

		tfui.RenderBreakSuccess(os.Stdout, lock)
		return nil
	},
}

func loadTFManager() (backend.LockManager, error) {
	if tfBackendTypeFlag == "" {
		mgr, _, err := detector.DetectAndLoad(tfStatePathFlag)
		return mgr, err
	}
	cfg := &detector.BackendConfig{Type: "s3", Config: map[string]interface{}{
		"bucket": tfS3BucketFlag,
		"key":    tfS3KeyFlag,
	}}
	switch tfBackendTypeFlag {
	case "s3-dynamodb":
		if tfTableNameFlag == "" {
			return nil, errors.New("--table-name is required for --backend-type s3-dynamodb")
		}
		cfg.Config["dynamodb_table"] = tfTableNameFlag
	case "s3-native":
		cfg.Config["use_lockfile"] = true
	default:
		return nil, fmt.Errorf("unsupported --backend-type %q: use s3-dynamodb or s3-native", tfBackendTypeFlag)
	}
	return detector.NewLockManager(cfg)
}

func verifyTFRunner(ctx context.Context, force bool) error {
	if tfGitHubRunIDFlag == "" {
		return nil
	}
	checker := &ghrun.Checker{BaseURL: tfGitHubAPIURLFlag, Token: tfGitHubTokenFlag}
	return safety.VerifyRunnerTerminated(ctx, checker, tfGitHubRepoFlag, tfGitHubRunIDFlag, force)
}

func init() {
	// Persistent flags on `x7 tf`
	pf := tfCmd.PersistentFlags()
	pf.StringVarP(&tfStatePathFlag, "state", "s", ".terraform/terraform.tfstate", "Path to .terraform/terraform.tfstate")
	pf.StringVar(&tfBackendTypeFlag, "backend-type", "", "Backend type override (s3-dynamodb, s3-native)")
	pf.StringVar(&tfTableNameFlag, "table-name", "", "DynamoDB lock table name (with --backend-type s3-dynamodb)")
	pf.StringVar(&tfS3BucketFlag, "s3-bucket", "", "S3 bucket of the Terraform state")
	pf.StringVar(&tfS3KeyFlag, "s3-key", "", "S3 key of the Terraform state")
	pf.StringVar(&tfGitHubTokenFlag, "github-token", os.Getenv("GITHUB_TOKEN"), "GitHub token to verify lock holder's workflow run")
	pf.StringVar(&tfGitHubRepoFlag, "github-repo", os.Getenv("GITHUB_REPOSITORY"), "owner/name of GitHub repository")
	pf.StringVar(&tfGitHubRunIDFlag, "github-run-id", "", "Workflow run ID of the lock holder")
	pf.StringVar(&tfGitHubAPIURLFlag, "github-api-url", ghrun.DefaultAPIURL, "GitHub API base URL")
	pf.DurationVar(&tfStaleAfterFlag, "stale-after", safety.DefaultStaleThreshold, "Staleness threshold before lock is considered stale (e.g. 30m, 1h)")
	pf.BoolVar(&tfDryRunFlag, "dry-run", false, "Preview operation safely without releasing remote lock")
	pf.BoolVar(&tfJSONFlag, "json", false, "Output machine-readable JSON for CI/CD automation")

	// Flags for tf unlock
	tfUnlockCmd.Flags().StringVar(&tfLockIDFlag, "lock-id", "", "Expected lock ID to verify against active lock before breaking")
	tfUnlockCmd.Flags().BoolVarP(&tfForceFlag, "force", "f", false, "Force break active locks without staleness or confirmation checks")
	tfUnlockCmd.Flags().BoolVarP(&tfYesFlag, "yes", "y", false, "Automatically answer yes to interactive confirmation prompts")

	tfCmd.AddCommand(tfInspectCmd)
	tfCmd.AddCommand(tfUnlockCmd)

	RootCmd.AddCommand(tfCmd)
}
