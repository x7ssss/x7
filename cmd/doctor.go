package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/x7ssss/x7/internal/engine/db"
	"github.com/x7ssss/x7/internal/engine/infra"
	"github.com/x7ssss/x7/internal/engine/k8s"
	"github.com/x7ssss/x7/pkg/triage"
)

var (
	doctorAllFlag       bool
	doctorSubsystemFlag string
	doctorOutputFlag    string
)

// GetAllEngines constructs and returns all built-in doctor engines.
func GetAllEngines() []triage.DoctorEngine {
	return []triage.DoctorEngine{
		// Kubernetes subsystem
		k8s.NewUnstuckEngine(),
		k8s.NewHelmEngine(),
		k8s.NewCRDEngine(),
		k8s.NewDNSEngine(),
		k8s.NewGitOpsEngine(),

		// Databases and storage subsystem
		db.NewPGWalEngine(),
		db.NewPGXidEngine(),
		db.NewClickHouseEngine(),

		// Cloud, state, and messaging subsystem
		infra.NewVPCDrainEngine(),
		infra.NewTFLockEngine(),
		infra.NewKafkaEngine(),
		infra.NewCgroupEngine(),
	}
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run concurrent triage inspection across infrastructure subsystems",
	Long: `Doctor concurrently executes diagnostic engines with a bounded worker pool
and hard 10-second per-check timeouts, isolating failures and detecting deadlocks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag)
		defer cancel()

		coordinator := triage.NewCoordinator(GetAllEngines()...)

		var subsystems []triage.Subsystem
		if doctorSubsystemFlag != "" {
			subsystems = append(subsystems, triage.Subsystem(doctorSubsystemFlag))
		}

		results, err := coordinator.Run(ctx, subsystems...)
		if err != nil {
			return fmt.Errorf("triage run failed: %w", err)
		}

		formatter := triage.NewFormatter()
		if doctorOutputFlag == "json" {
			if err := formatter.FormatJSON(os.Stdout, results); err != nil {
				return err
			}
		} else {
			formatter.FormatText(os.Stdout, results)
		}

		for _, r := range results {
			if r.Severity == triage.SeverityDeadlock || r.Severity == triage.SeverityCritical {
				os.Exit(1)
			}
		}

		return nil
	},
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorAllFlag, "all", true, "Run checks across all subsystems")
	doctorCmd.Flags().StringVar(&doctorSubsystemFlag, "subsystem", "", "Restrict triage to specific subsystem ('k8s', 'db', 'infra')")
	doctorCmd.Flags().StringVarP(&doctorOutputFlag, "output", "o", "text", "Output format ('text' or 'json')")
	RootCmd.AddCommand(doctorCmd)
}
