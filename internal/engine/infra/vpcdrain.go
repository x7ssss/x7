package infra

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/x7ssss/x7/pkg/triage"
)

// NetworkInterfaceItem represents an ENI entry returned by AWS EC2 API.
type NetworkInterfaceItem struct {
	NetworkInterfaceID string `xml:"networkInterfaceId"`
	Status             string `xml:"status"`
	Description        string `xml:"description"`
	SubnetID           string `xml:"subnetId"`
	PrivateIPAddress   string `xml:"privateIpAddress"`
}

// DescribeNetworkInterfacesResponse parses the XML response from EC2.
type DescribeNetworkInterfacesResponse struct {
	XMLName             xml.Name               `xml:"DescribeNetworkInterfacesResponse"`
	NetworkInterfaceSet []NetworkInterfaceItem `xml:"networkInterfaceSet>item"`
}

// VPCDrainEngine detects unattached available ENIs locking VPC subnet IPv4 addresses.
type VPCDrainEngine struct{}

func NewVPCDrainEngine() *VPCDrainEngine {
	return &VPCDrainEngine{}
}

func (e *VPCDrainEngine) Name() string {
	return "infra-vpcdrain"
}

func (e *VPCDrainEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemInfra
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func (e *VPCDrainEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}

	if accessKey == "" || secretKey == "" {
		return []triage.DiagnosticResult{
			{
				ID:         "infra-vpcdrain-unconfigured",
				Subsystem:  triage.SubsystemInfra,
				Target:     "AWS VPC ENIs",
				Severity:   triage.SeverityOK,
				Summary:    "No AWS credentials configured in environment; skipped",
				Remediable: false,
			},
		}, nil
	}

	// Pure Go standard library AWS SigV4 signed request
	host := fmt.Sprintf("ec2.%s.amazonaws.com", region)
	endpoint := fmt.Sprintf("https://%s/", host)
	payload := "Action=DescribeNetworkInterfaces&Version=2016-11-15"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create ec2 request failed: %w", err)
	}

	now := time.Now().UTC()
	dateStamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("x-amz-date", amzDate)

	payloadHashBytes := sha256.Sum256([]byte(payload))
	payloadHash := hex.EncodeToString(payloadHashBytes[:])
	req.Header.Set("x-amz-content-sha256", payloadHash)

	canonicalHeaders := fmt.Sprintf("content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", host, payloadHash, amzDate)
	signedHeaders := "content-type;host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := fmt.Sprintf("POST\n/\n\n%s\n%s\n%s", canonicalHeaders, signedHeaders, payloadHash)

	reqHashBytes := sha256.Sum256([]byte(canonicalRequest))
	reqHash := hex.EncodeToString(reqHashBytes[:])

	credentialScope := fmt.Sprintf("%s/%s/ec2/aws4_request", dateStamp, region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, credentialScope, reqHash)

	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "ec2")
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ec2 api call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ec2 api returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var xmlResp DescribeNetworkInterfacesResponse
	if decErr := xml.NewDecoder(resp.Body).Decode(&xmlResp); decErr != nil {
		return nil, fmt.Errorf("failed to decode ec2 xml response: %w", decErr)
	}

	results := make([]triage.DiagnosticResult, 0)

	for _, eni := range xmlResp.NetworkInterfaceSet {
		// Detect unattached, available ENIs matching aws-K8S-* description
		isAvailable := strings.EqualFold(eni.Status, "available")
		isK8sENI := strings.Contains(eni.Description, "aws-K8S-") || strings.HasPrefix(eni.Description, "aws-K8S-")

		if isAvailable && isK8sENI {
			eniID := eni.NetworkInterfaceID
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("infra-vpcdrain-%s", eniID),
				Subsystem:  triage.SubsystemInfra,
				Target:     fmt.Sprintf("ENI '%s' (Subnet: %s, IP: %s)", eniID, eni.SubnetID, eni.PrivateIPAddress),
				Severity:   triage.SeverityDeadlock,
				Summary:    "Unattached available ENI leaking VPC subnet IPv4 address",
				Details:    fmt.Sprintf("ENI '%s' with description '%s' is unattached (available) in subnet '%s', consuming an IPv4 address.", eniID, eni.Description, eni.SubnetID),
				Remediable: true,
				RemediateFn: func(remCtx context.Context, dryRun bool) error {
					if dryRun {
						return nil
					}
					// Send DeleteNetworkInterface request
					delPayload := fmt.Sprintf("Action=DeleteNetworkInterface&NetworkInterfaceId=%s&Version=2016-11-15", eniID)
					delReq, _ := http.NewRequestWithContext(remCtx, http.MethodPost, endpoint, strings.NewReader(delPayload))
					delReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
					delResp, delErr := client.Do(delReq)
					if delErr != nil {
						return delErr
					}
					defer delResp.Body.Close()
					return nil
				},
			})
		}
	}

	if len(results) == 0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "infra-vpcdrain-nominal",
			Subsystem:  triage.SubsystemInfra,
			Target:     fmt.Sprintf("VPC ENIs (%s)", region),
			Severity:   triage.SeverityOK,
			Summary:    "No unattached available ENIs locking subnet addresses",
			Remediable: false,
		})
	}

	return results, nil
}
