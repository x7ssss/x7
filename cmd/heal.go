package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/x7ssss/x7/pkg/remediation"
	"github.com/x7ssss/x7/pkg/triage"
)

var (
	healDryRunFlag      bool
	healInteractiveFlag bool
	healSubsystemFlag   string
	healForceFlag       bool
)

var healCmd = &cobra.Command{
	Use:   "heal [subsystem]",
	Short: "Interactive or automated safe two-phase remediation",
	Long: `Heal runs diagnostic triage, evaluates remediable issues, previews fixes
using safe dry-run validation, and applies corrective actions.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag)
		defer cancel()

		var subsystems []triage.Subsystem
		targetSub := healSubsystemFlag
		if len(args) > 0 && args[0] != "" {
			targetSub = args[0]
		}
		if targetSub != "" {
			subsystems = append(subsystems, triage.Subsystem(targetSub))
		}

		fmt.Println("[x7 triage] Scanning infrastructure for remediable anomalies...")
		coordinator := triage.NewCoordinator(GetAllEngines()...)
		results, err := coordinator.Run(ctx, subsystems...)
		if err != nil {
			return fmt.Errorf("triage run before heal failed: %w", err)
		}

		actions := remediation.FilterRemediable(results)
		if len(actions) == 0 {
			fmt.Println("No remediable production issues or deadlocks detected.")
			return nil
		}

		cfg := remediation.ExecutorConfig{
			DryRun:      healDryRunFlag,
			Interactive: healInteractiveFlag,
			Force:       healForceFlag,
			In:          os.Stdin,
			Out:         os.Stdout,
		}

		executor := remediation.NewExecutor(cfg)
		_, execErr := executor.Execute(ctx, actions)
		if execErr != nil {
			return fmt.Errorf("remediation execution error: %w", execErr)
		}

		return nil
	},
}

func init() {
	healCmd.Flags().BoolVar(&healDryRunFlag, "dry-run", true, "Preview remediation changes without applying")
	healCmd.Flags().BoolVar(&healInteractiveFlag, "interactive", false, "Interactively prompt (y/N) before applying each fix")
	healCmd.Flags().StringVar(&healSubsystemFlag, "subsystem", "", "Target specific subsystem ('k8s', 'db', 'infra')")
	healCmd.Flags().BoolVar(&healForceFlag, "force", false, "Bypass confirmation prompts for CI/CD automation")
	RootCmd.AddCommand(healCmd)
}
