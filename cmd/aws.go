package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"
	"github.com/x7ssss/x7/pkg/remediation/aws/awsclient"
	"github.com/x7ssss/x7/pkg/remediation/aws/engine"
	"github.com/x7ssss/x7/pkg/remediation/aws/locking"
	"github.com/x7ssss/x7/pkg/remediation/aws/logger"
	"github.com/x7ssss/x7/pkg/remediation/aws/reporting"
	"github.com/x7ssss/x7/pkg/remediation/aws/safety"
	"github.com/x7ssss/x7/pkg/ui"
)

var (
	awsVpcIDFlag       string
	awsTagFlag         string
	awsAccountIDFlag   string
	awsRegionFlag      string
	awsDryRunFlag      bool
	awsJSONFlag        bool
	awsLockTableFlag   string
	awsEmitSummaryFlag bool
)

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Remediation and drainage engines for AWS cloud infrastructure",
	Long: `Autonomous remediation engines for AWS cloud networking, VPCs, ENIs,
load balancers, security group dependency cycles, and orphaned cloud resources.`,
}

var awsVpcDrainCmd = &cobra.Command{
	Use:     "vpc-drain",
	Aliases: []string{"vpcdrain"},
	Short:   "Deterministic 8-tier ephemeral AWS VPC teardown engine",
	Long: `VPC Drain performs non-blocking discovery and deterministic dependency-ordered
sweeping of VPC resources (NAT Gateways, ALBs/NLBs, ECS/Lambda, ENIs, Security Groups, Subnets).
Enforces blast radius validation, ambient account ID matching, tag scoping, and DynamoDB mutex locks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(awsVpcIDFlag) == "" {
			return fmt.Errorf("missing required flag: --vpc-id")
		}
		if !strings.HasPrefix(awsVpcIDFlag, "vpc-") {
			return fmt.Errorf("invalid --vpc-id format %q: expected string starting with 'vpc-'", awsVpcIDFlag)
		}
		if strings.TrimSpace(awsTagFlag) == "" {
			return fmt.Errorf("missing required flag: --tag")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigChan
			cancel()
		}()

		logLevel := logger.LevelInfo
		log := logger.NewLogger(logLevel, awsJSONFlag)

		var optFns []func(*awsconfig.LoadOptions) error
		if awsRegionFlag != "" {
			optFns = append(optFns, awsconfig.WithRegion(awsRegionFlag))
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

		clients := awsclient.NewClients(awsCfg)

		// 1. Safety Guardrails Verification
		log.Info("Running safety guardrails verification...")
		guard := safety.NewGuard(clients.STS, clients.EC2)
		safetyResult, err := guard.VerifyAll(ctx, awsVpcIDFlag, awsAccountIDFlag, awsTagFlag)
		if err != nil {
			return fmt.Errorf("safety guardrail check failed: %w", err)
		}

		log.Success("Safety guardrails passed: Account %s (Caller: %s)", safetyResult.CallerAccountID, safetyResult.CallerArn)

		// 2. Distributed DynamoDB Mutex Lock (if configured)
		var locker *locking.DynamoLocker
		if awsLockTableFlag != "" {
			locker = locking.NewDynamoLocker(clients.DynamoDB, awsLockTableFlag, log)
			if err := locker.AcquireLock(ctx, awsVpcIDFlag, "", locking.DefaultLeaseDuration); err != nil {
				return err
			}
			defer func() {
				releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer releaseCancel()
				_ = locker.ReleaseLock(releaseCtx, awsVpcIDFlag)
			}()
		}

		// 3. Discover VPC Resources
		log.Info("Discovering all resources in VPC %s...", awsVpcIDFlag)
		inventory, err := engine.DiscoverVPCResources(ctx, clients, awsVpcIDFlag, resolvedRegion, safetyResult.CallerAccountID, safetyResult.VpcTags)
		if err != nil {
			return fmt.Errorf("discovery failed: %w", err)
		}

		// 4. Build 8-Tier Teardown Manifest
		manifest := engine.BuildManifest(inventory)

		// 5. Handle Dry-Run Mode
		if awsDryRunFlag {
			if awsJSONFlag {
				jsonBytes, err := engine.FormatJSON(manifest)
				if err != nil {
					return fmt.Errorf("failed to serialize dry-run manifest: %w", err)
				}
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Print(engine.FormatTerminal(manifest))
			}

			if awsEmitSummaryFlag || os.Getenv("GITHUB_STEP_SUMMARY") != "" {
				swept := buildSweptResourcesSummary(inventory, safetyResult.CallerAccountID, resolvedRegion, 0)
				_ = reporting.EmitGitHubSummary(swept, "")
			}

			return nil
		}

		// 6. Execute Real Teardown
		startTime := time.Now()
		sweeperOpts := engine.DefaultSweeperOptions(log)
		sweeper := engine.NewSweeper(clients, sweeperOpts)

		if err := sweeper.Execute(ctx, inventory); err != nil {
			return fmt.Errorf("teardown execution failed: %w", err)
		}

		durationSeconds := int(time.Since(startTime).Seconds())
		swept := buildSweptResourcesSummary(inventory, safetyResult.CallerAccountID, resolvedRegion, durationSeconds)

		// 7. Emit FinOps Summary
		if awsEmitSummaryFlag || os.Getenv("GITHUB_STEP_SUMMARY") != "" {
			if err := reporting.EmitGitHubSummary(swept, ""); err != nil {
				log.Warn("Failed to emit GitHub step summary: %v", err)
			} else {
				log.Success("FinOps step summary appended to $GITHUB_STEP_SUMMARY")
			}
		}

		if awsJSONFlag {
			return ui.PrintJSONStdout(swept)
		}

		savings := reporting.CalculateSavings(swept)
		if savings.TotalMonthly > 0 {
			log.Success("FinOps Impact: Prevented $%.2f/month in cloud waste ($%.2f annualized)",
				savings.TotalMonthly, savings.TotalAnnualized)
		}

		return nil
	},
}

func buildSweptResourcesSummary(inv *engine.VPCInventory, accountID string, region string, durationSec int) reporting.SweptResources {
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

func init() {
	pf := awsCmd.PersistentFlags()
	pf.StringVar(&awsRegionFlag, "region", "", "AWS region (defaults to ambient AWS config or AWS_REGION)")
	pf.StringVar(&awsAccountIDFlag, "account-id", "", "Expected AWS Account ID to prevent cross-account blast radius")
	pf.BoolVar(&awsDryRunFlag, "dry-run", true, "Inspect VPC and build DAG without modifying cloud resources")
	pf.BoolVar(&awsJSONFlag, "json", false, "Output machine-readable JSON for CI/CD automation")

	awsVpcDrainCmd.Flags().StringVar(&awsVpcIDFlag, "vpc-id", "", "Required target VPC ID (e.g. vpc-0123456789abcdef0)")
	awsVpcDrainCmd.Flags().StringVar(&awsTagFlag, "tag", "", "Required scope tag in Key=Value format (e.g. Ephemeral=true)")
	awsVpcDrainCmd.Flags().StringVar(&awsLockTableFlag, "lock-table", "", "DynamoDB table name for distributed mutex locking")
	awsVpcDrainCmd.Flags().BoolVar(&awsEmitSummaryFlag, "emit-summary", false, "Emit FinOps cost summary to $GITHUB_STEP_SUMMARY or stdout")

	awsCmd.AddCommand(awsVpcDrainCmd)
	RootCmd.AddCommand(awsCmd)
}
