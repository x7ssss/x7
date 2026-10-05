package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
	"github.com/x7ssss/x7/pkg/remediation/aws/engine"
	"github.com/x7ssss/x7/pkg/remediation/aws/locking"
	"github.com/x7ssss/x7/pkg/remediation/aws/logger"
	"github.com/x7ssss/x7/pkg/remediation/aws/reporting"
	"github.com/x7ssss/x7/pkg/remediation/aws/safety"
)

var (
	// Version is injected during compilation via -ldflags
	Version = "1.0.0"
)

// Run executes the vpcdrain CLI application with the given arguments.
func Run(args []string) error {
	fs := flag.NewFlagSet("vpcdrain", flag.ContinueOnError)

	vpcID := fs.String("vpc-id", "", "Required target VPC ID (e.g., vpc-0123456789abcdef0)")
	tag := fs.String("tag", "", "Required scope tag in Key=Value format (e.g., PR=123 or Ephemeral=true)")
	accountID := fs.String("account-id", "", "Expected AWS Account ID to prevent cross-account blast radius")
	region := fs.String("region", "", "AWS region (defaults to ambient AWS config or AWS_REGION)")
	dryRun := fs.Bool("dry-run", true, "Inspect VPC, build DAG, and output manifest without modifying resources")
	format := fs.String("format", "terminal", "Output format: terminal or json")
	lockTable := fs.String("lock-table", "", "DynamoDB table name for distributed mutex locking")
	emitSummary := fs.Bool("emit-summary", false, "Emit FinOps cost summary to $GITHUB_STEP_SUMMARY or terminal")
	showVersion := fs.Bool("version", false, "Print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `vpcdrain - Deterministic 8-Tier AWS Ephemeral VPC Teardown Engine

Usage:
  vpcdrain --vpc-id <vpc-id> --tag <Key=Value> [flags]

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), `
Examples:
  # Dry-run inspection with formatted terminal output (default)
  vpcdrain --vpc-id vpc-0123456789abcdef0 --tag Ephemeral=true

  # Dry-run inspection outputting pure JSON manifest
  vpcdrain --vpc-id vpc-0123456789abcdef0 --tag PR=42 --format json

  # Execute real deterministic teardown with DynamoDB locking and GitHub summary
  vpcdrain --vpc-id vpc-0123456789abcdef0 --tag PR=42 --account-id 123456789012 \
    --lock-table vpcdrain-locks --emit-summary --dry-run=false
`)
	}

	if err := fs.Parse(args); err != nil {
		if strings.Contains(err.Error(), "help requested") {
			return nil
		}
		return err
	}

	if *showVersion {
		fmt.Printf("vpcdrain v%s\n", Version)
		return nil
	}

	// 1. Validate required flags
	if strings.TrimSpace(*vpcID) == "" {
		fs.Usage()
		return fmt.Errorf("missing required flag: --vpc-id")
	}

	if !strings.HasPrefix(*vpcID, "vpc-") {
		return fmt.Errorf("invalid --vpc-id format %q: expected string starting with 'vpc-'", *vpcID)
	}

	if strings.TrimSpace(*tag) == "" {
		fs.Usage()
		return fmt.Errorf("missing required flag: --tag")
	}

	if *format != "terminal" && *format != "json" {
		return fmt.Errorf("invalid --format %q: must be 'terminal' or 'json'", *format)
	}

	// 2. Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// 3. Initialize Logger
	isJSON := *format == "json"
	logLevel := logger.LevelInfo
	log := logger.NewLogger(logLevel, isJSON)

	// 4. Load AWS SDK Configuration
	var optFns []func(*awsconfig.LoadOptions) error
	if *region != "" {
		optFns = append(optFns, awsconfig.WithRegion(*region))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	resolvedRegion := awsCfg.Region
	if resolvedRegion == "" {
		resolvedRegion = os.Getenv("AWS_REGION")
		if resolvedRegion == "" {
			resolvedRegion = os.Getenv("AWS_DEFAULT_REGION")
		}
	}

	// 5. Initialize AWS Service Clients
	clients := awsclient.NewClients(awsCfg)

	// 6. Safety Guardrails Verification
	log.Info("Running safety guardrails verification...")
	guard := safety.NewGuard(clients.STS, clients.EC2)
	safetyResult, err := guard.VerifyAll(ctx, *vpcID, *accountID, *tag)
	if err != nil {
		return fmt.Errorf("safety guardrail check failed: %w", err)
	}

	log.Success("Safety guardrails passed: Account %s (Caller: %s)", safetyResult.CallerAccountID, safetyResult.CallerArn)

	// 7. Distributed DynamoDB Mutex Lock (if configured)
	var locker *locking.DynamoLocker
	if *lockTable != "" {
		locker = locking.NewDynamoLocker(clients.DynamoDB, *lockTable, log)
		if err := locker.AcquireLock(ctx, *vpcID, "", locking.DefaultLeaseDuration); err != nil {
			return err
		}
		// Ensure clean lock release upon completion or unexpected failure
		defer func() {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer releaseCancel()
			_ = locker.ReleaseLock(releaseCtx, *vpcID)
		}()
	}

	// 8. Discover VPC Resources
	log.Info("Discovering all resources in VPC %s...", *vpcID)
	inventory, err := engine.DiscoverVPCResources(ctx, clients, *vpcID, resolvedRegion, safetyResult.CallerAccountID, safetyResult.VpcTags)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	// 9. Build 8-Tier Teardown Manifest
	manifest := engine.BuildManifest(inventory)

	// 10. Handle Dry-Run Mode
	if *dryRun {
		if *format == "json" {
			jsonBytes, err := engine.FormatJSON(manifest)
			if err != nil {
				return fmt.Errorf("failed to serialize dry-run manifest: %w", err)
			}
			fmt.Println(string(jsonBytes))
		} else {
			fmt.Print(engine.FormatTerminal(manifest))
		}

		if *emitSummary || os.Getenv("GITHUB_STEP_SUMMARY") != "" {
			swept := buildSweptResources(inventory, safetyResult.CallerAccountID, resolvedRegion, 0)
			_ = reporting.EmitGitHubSummary(swept, "")
		}

		return nil
	}

	// 11. Execute Real Teardown
	startTime := time.Now()
	sweeperOpts := engine.DefaultSweeperOptions(log)
	sweeper := engine.NewSweeper(clients, sweeperOpts)

	if err := sweeper.Execute(ctx, inventory); err != nil {
		return fmt.Errorf("teardown execution failed: %w", err)
	}

	durationSeconds := int(time.Since(startTime).Seconds())
	swept := buildSweptResources(inventory, safetyResult.CallerAccountID, resolvedRegion, durationSeconds)

	// 12. Emit FinOps Summary
	if *emitSummary || os.Getenv("GITHUB_STEP_SUMMARY") != "" {
		if err := reporting.EmitGitHubSummary(swept, ""); err != nil {
			log.Warn("Failed to emit GitHub step summary: %v", err)
		} else {
			log.Success("FinOps step summary appended to $GITHUB_STEP_SUMMARY")
		}
	}

	if *format == "terminal" {
		savings := reporting.CalculateSavings(swept)
		if savings.TotalMonthly > 0 {
			log.Success("FinOps Impact: Prevented $%.2f/month in cloud waste ($%.2f annualized)",
				savings.TotalMonthly, savings.TotalAnnualized)
		}
	}

	return nil
}

func buildSweptResources(inv *engine.VPCInventory, accountID string, region string, durationSec int) reporting.SweptResources {
	var ec2Count int
	if inv != nil {
		ec2Count = len(inv.ECSTasks) + len(inv.ECSServices)
	}

	return reporting.SweptResources{
		VpcID:            inv.VpcID,
		Region:           region,
		AccountID:        accountID,
		NatGateways:      len(inv.NatGateways),
		ElasticIPs:       len(inv.ElasticIPs),
		LoadBalancers:    len(inv.LoadBalancers),
		EC2Instances:     ec2Count,
		VpcEndpoints:     len(inv.VpcEndpoints),
		SecurityGroups:   len(inv.SecurityGroups),
		Subnets:          len(inv.Subnets),
		RouteTables:      len(inv.RouteTables),
		InternetGateways: len(inv.InternetGateways),
		DurationSeconds:  durationSec,
	}
}
