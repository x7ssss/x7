package engine

// TargetInfo defines the target AWS environment and VPC.
type TargetInfo struct {
	AccountID string            `json:"accountId"`
	Region    string            `json:"region"`
	VpcID     string            `json:"vpcId"`
	Tags      map[string]string `json:"tags"`
}

// BlastRadiusSummary summarizes the scope and projected impact of the teardown.
type BlastRadiusSummary struct {
	TotalResourcesToDelete   int `json:"totalResourcesToDelete"`
	TotalRulesToStrip        int `json:"totalRulesToStrip"`
	EstimatedDurationSeconds int `json:"estimatedDurationSeconds"`
}

// PlanAction describes a single action against a specific AWS resource.
type PlanAction struct {
	ResourceID string `json:"resourceId"`
	Service    string `json:"service"`
	Action     string `json:"action"`
	Details    string `json:"details,omitempty"`
}

// ExecutionTier describes one tier in the 8-tier reverse topological order.
type ExecutionTier struct {
	Tier        int          `json:"tier"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Resources   []PlanAction `json:"resources"`
}

// DryRunManifest is the root JSON structure representing the complete teardown execution plan.
type DryRunManifest struct {
	Target             TargetInfo         `json:"target"`
	BlastRadiusSummary BlastRadiusSummary `json:"blastRadiusSummary"`
	ExecutionPlan      []ExecutionTier    `json:"executionPlan"`
}

// ECSServiceRef holds references to ECS services within the VPC.
type ECSServiceRef struct {
	ClusterArn   string `json:"clusterArn"`
	ServiceArn   string `json:"serviceArn"`
	ServiceName  string `json:"serviceName"`
	DesiredCount int32  `json:"desiredCount"`
}

// ECSTaskRef holds references to active ECS tasks running in the VPC.
type ECSTaskRef struct {
	ClusterArn string `json:"clusterArn"`
	TaskArn    string `json:"taskArn"`
}

// LambdaFuncRef holds references to Lambda functions configured with VPC subnets.
type LambdaFuncRef struct {
	FunctionName string `json:"functionName"`
	FunctionArn  string `json:"functionArn"`
}

// LBRef holds references to Elastic Load Balancers in the VPC.
type LBRef struct {
	LoadBalancerArn  string `json:"loadBalancerArn"`
	LoadBalancerName string `json:"loadBalancerName"`
	Type             string `json:"type"`
}

// TargetGroupRef holds references to ELB Target Groups in the VPC.
type TargetGroupRef struct {
	TargetGroupArn  string `json:"targetGroupArn"`
	TargetGroupName string `json:"targetGroupName"`
}

// NatGatewayRef holds references to NAT Gateways in the VPC.
type NatGatewayRef struct {
	NatGatewayID  string   `json:"natGatewayId"`
	State         string   `json:"state"`
	AllocationIDs []string `json:"allocationIds"`
}

// SecurityGroupRef holds references to Security Groups and their rule counts.
type SecurityGroupRef struct {
	GroupID           string `json:"groupId"`
	GroupName         string `json:"groupName"`
	IngressRulesCount int    `json:"ingressRulesCount"`
	EgressRulesCount  int    `json:"egressRulesCount"`
	IsDefault         bool   `json:"isDefault"`
}

// RouteTableAssocRef holds route table association details.
type RouteTableAssocRef struct {
	AssociationID string `json:"associationId"`
	SubnetID      string `json:"subnetId,omitempty"`
	Main          bool   `json:"main"`
}

// RouteTableRef holds references to Route Tables in the VPC.
type RouteTableRef struct {
	RouteTableID string               `json:"routeTableId"`
	IsMain       bool                 `json:"isMain"`
	Associations []RouteTableAssocRef `json:"associations"`
}

// ENIRef holds information about a Network Interface in the VPC.
type ENIRef struct {
	NetworkInterfaceID string `json:"networkInterfaceId"`
	InterfaceType      string `json:"interfaceType"`
	Description        string `json:"description"`
	OwnerID            string `json:"ownerId"`
	SubnetID           string `json:"subnetId"`
	ParentService      string `json:"parentService"`
}

// VPCInventory stores all discovered resources across the VPC.
type VPCInventory struct {
	VpcID   string
	Region  string
	Account string
	Tags    map[string]string

	// Tier 1: Compute
	ECSServices []ECSServiceRef
	ECSTasks    []ECSTaskRef
	LambdaFuncs []LambdaFuncRef

	// Tier 2: Ingress
	LoadBalancers []LBRef
	TargetGroups  []TargetGroupRef
	VpcEndpoints  []string

	// Tier 3: Egress
	NatGateways    []NatGatewayRef
	TGWAttachments []string
	PeeringConns   []string

	// Tier 4: Elastic IPs
	ElasticIPs []string

	// Tier 5 & 6: Security Groups & Route Tables
	SecurityGroups []SecurityGroupRef
	RouteTables    []RouteTableRef

	// Tier 7: Gateways & Subnets
	InternetGateways []string
	Subnets          []string

	// Requester-managed ENIs
	ActiveENIs []ENIRef
}
