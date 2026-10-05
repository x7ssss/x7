package reporting

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Standard monthly unit rates in USD ($) based on AWS pricing (730 hours/month).
const (
	RateNatGatewayMonthly    = 32.85 // $0.045 / hour
	RateElasticIPMonthly     = 3.65  // $0.005 / hour IPv4 charge
	RateLoadBalancerMonthly  = 18.25 // $0.025 / hour
	RateEC2InstanceMonthly   = 40.00 // Average monthly t3/t4g compute instance
	RateVpcEndpointMonthly   = 7.30  // $0.010 / hour
)

// SweptResources holds counts of resources destroyed during the teardown execution.
type SweptResources struct {
	VpcID            string
	Region           string
	AccountID        string
	NatGateways      int
	ElasticIPs       int
	LoadBalancers    int
	EC2Instances     int
	VpcEndpoints     int
	SecurityGroups   int
	Subnets          int
	RouteTables      int
	InternetGateways int
	DurationSeconds  int
}

// CostItem holds financial calculations for a single resource category.
type CostItem struct {
	Category        string
	Quantity        int
	MonthlyUnitRate float64
	MonthlySavings  float64
	AnnualSavings   float64
}

// CostSavings holds the full financial breakdown of prevented cloud waste.
type CostSavings struct {
	Items           []CostItem
	TotalMonthly    float64
	TotalAnnualized float64
}

// CalculateSavings computes monthly and annualized cost reductions.
func CalculateSavings(r SweptResources) CostSavings {
	var items []CostItem
	var totalMonthly float64

	categories := []struct {
		name string
		qty  int
		rate float64
	}{
		{"NAT Gateways", r.NatGateways, RateNatGatewayMonthly},
		{"Elastic IPs (IPv4)", r.ElasticIPs, RateElasticIPMonthly},
		{"Application / Network Load Balancers", r.LoadBalancers, RateLoadBalancerMonthly},
		{"Running EC2 / Fargate Workloads", r.EC2Instances, RateEC2InstanceMonthly},
		{"VPC Interface Endpoints", r.VpcEndpoints, RateVpcEndpointMonthly},
	}

	for _, c := range categories {
		if c.qty > 0 {
			monthly := float64(c.qty) * c.rate
			annual := monthly * 12.0
			items = append(items, CostItem{
				Category:        c.name,
				Quantity:        c.qty,
				MonthlyUnitRate: c.rate,
				MonthlySavings:  monthly,
				AnnualSavings:   annual,
			})
			totalMonthly += monthly
		}
	}

	return CostSavings{
		Items:           items,
		TotalMonthly:    totalMonthly,
		TotalAnnualized: totalMonthly * 12.0,
	}
}

// GenerateMarkdownSummary creates a clean GitHub Flavored Markdown summary report.
func GenerateMarkdownSummary(r SweptResources) string {
	savings := CalculateSavings(r)
	var sb strings.Builder

	sb.WriteString("## 💸 FinOps VPC Teardown Summary\n\n")
	sb.WriteString(fmt.Sprintf("> **Target VPC:** `%s` &nbsp; | &nbsp; **Region:** `%s` &nbsp; | &nbsp; **Account:** `%s`\n\n",
		r.VpcID, r.Region, r.AccountID))

	if len(savings.Items) == 0 {
		sb.WriteString("No billable standalone resources (NAT Gateways, ELBs, EIPs, VPC Endpoints) were active.\n\n")
	} else {
		sb.WriteString("| Billable Resource Category | Destroyed | Unit Monthly Rate | Monthly Savings | Annualized Savings |\n")
		sb.WriteString("| :------------------------- | :-------: | :---------------: | :-------------: | :----------------: |\n")

		for _, item := range savings.Items {
			sb.WriteString(fmt.Sprintf("| **%s** | %d | $%.2f | **$%.2f** | $%.2f |\n",
				item.Category, item.Quantity, item.MonthlyUnitRate, item.MonthlySavings, item.AnnualSavings))
		}

		sb.WriteString(fmt.Sprintf("| **Total Prevented Cloud Waste** | | | **$%.2f / mo** | **$%.2f / yr** |\n\n",
			savings.TotalMonthly, savings.TotalAnnualized))

		sb.WriteString(fmt.Sprintf("💰 **Total Monthly Savings:** **$%.2f** ($%.2f annualized)\n\n",
			savings.TotalMonthly, savings.TotalAnnualized))
	}

	sb.WriteString("### 📦 Infrastructure Swept\n\n")
	sb.WriteString("| Resource Type | Count |\n")
	sb.WriteString("| :------------ | :---: |\n")
	sb.WriteString(fmt.Sprintf("| Subnets | %d |\n", r.Subnets))
	sb.WriteString(fmt.Sprintf("| Security Groups | %d |\n", r.SecurityGroups))
	sb.WriteString(fmt.Sprintf("| Route Tables | %d |\n", r.RouteTables))
	sb.WriteString(fmt.Sprintf("| Internet Gateways | %d |\n", r.InternetGateways))
	if r.NatGateways > 0 {
		sb.WriteString(fmt.Sprintf("| NAT Gateways | %d |\n", r.NatGateways))
	}
	if r.ElasticIPs > 0 {
		sb.WriteString(fmt.Sprintf("| Elastic IPs | %d |\n", r.ElasticIPs))
	}
	if r.LoadBalancers > 0 {
		sb.WriteString(fmt.Sprintf("| Load Balancers | %d |\n", r.LoadBalancers))
	}
	if r.VpcEndpoints > 0 {
		sb.WriteString(fmt.Sprintf("| VPC Endpoints | %d |\n", r.VpcEndpoints))
	}
	sb.WriteString(fmt.Sprintf("\n*Teardown completed deterministically in %d seconds at %s UTC.*\n",
		r.DurationSeconds, time.Now().UTC().Format("2006-01-02 15:04:05")))

	return sb.String()
}

// EmitGitHubSummary writes the Markdown summary to the file specified by filePath
// (defaulting to GITHUB_STEP_SUMMARY environment variable).
func EmitGitHubSummary(r SweptResources, filePath string) error {
	targetPath := filePath
	if targetPath == "" {
		targetPath = os.Getenv("GITHUB_STEP_SUMMARY")
	}

	if targetPath == "" {
		// Not running in GitHub Actions and no explicit output path provided
		return nil
	}

	content := GenerateMarkdownSummary(r)

	f, err := os.OpenFile(targetPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open step summary file %s: %w", targetPath, err)
	}
	defer f.Close()

	if _, err := f.WriteString(content + "\n"); err != nil {
		return fmt.Errorf("failed to write to step summary file %s: %w", targetPath, err)
	}

	return nil
}
