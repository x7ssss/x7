package cmd

import (
	"os"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/x7ssss/x7/pkg/ui"
)

var (
	// Version holds the current release version of x7.
	Version = "v1.0.0"

	// GitCommit holds the git commit hash injected at compile time.
	GitCommit = "unknown"

	// BuildDate holds the compilation timestamp.
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version, git commit, and runtime build info",
	Run: func(cmd *cobra.Command, args []string) {
		entries := [][2]string{
			{"Version", Version},
			{"Git Commit", GitCommit},
			{"Build Date", BuildDate},
			{"Go Runtime", runtime.Version()},
			{"Platform", runtime.GOOS + "/" + runtime.GOARCH},
			{"CGO Enabled", "0 (pure static)"},
			{"Engine Status", "Unified Diagnostic & Remediation Engine"},
		}

		ui.RenderCard(os.Stdout, "x7 Core Infrastructure Engine", entries)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
