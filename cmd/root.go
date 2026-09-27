package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/x7ssss/x7/internal/engine/k8s"
)

var (
	kubeconfigFlag string
	timeoutFlag    time.Duration
	verboseFlag    bool
)

// RootCmd is the primary Cobra command for x7.
var RootCmd = &cobra.Command{
	Use:   "x7",
	Short: "x7: Unified zero-dependency infrastructure triage and remediation engine",
	Long: `x7 (v1.0.0) is a single static binary providing deep diagnostic triage
and safe two-phase remediation across Kubernetes, databases, and cloud infrastructure.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if kubeconfigFlag != "" {
			k8s.GlobalKubeconfigPath = kubeconfigFlag
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVar(&kubeconfigFlag, "kubeconfig", "", "Path to the kubeconfig file")
	RootCmd.PersistentFlags().DurationVar(&timeoutFlag, "timeout", 30*time.Second, "Global command timeout")
	RootCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false, "Enable verbose diagnostic logging")
}
