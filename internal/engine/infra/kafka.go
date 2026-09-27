package infra

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/x7ssss/x7/pkg/triage"
)

// KafkaEngine inspects group coordinators at the wire level for PreparingRebalance storms.
type KafkaEngine struct{}

func NewKafkaEngine() *KafkaEngine {
	return &KafkaEngine{}
}

func (e *KafkaEngine) Name() string {
	return "infra-kafka"
}

func (e *KafkaEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemInfra
}

func writeKafkaString(w io.Writer, s string) {
	binary.Write(w, binary.BigEndian, int16(len(s)))
	w.Write([]byte(s))
}

func readKafkaString(r io.Reader) (string, error) {
	var length int16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}
	if length <= 0 {
		return "", nil
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func (e *KafkaEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	brokers := os.Getenv("KAFKA_BROKERS")
	if brokers == "" {
		brokers = os.Getenv("KAFKA_BOOTSTRAP_SERVERS")
	}
	if brokers == "" {
		brokers = os.Getenv("KAFKA_BROKER")
	}

	if brokers == "" {
		return []triage.DiagnosticResult{
			{
				ID:         "infra-kafka-unconfigured",
				Subsystem:  triage.SubsystemInfra,
				Target:     "Kafka Cluster",
				Severity:   triage.SeverityOK,
				Summary:    "No Kafka broker configured via KAFKA_BROKERS; skipped",
				Remediable: false,
			},
		}, nil
	}

	brokerList := strings.Split(brokers, ",")
	primaryBroker := strings.TrimSpace(brokerList[0])
	if !strings.Contains(primaryBroker, ":") {
		primaryBroker = primaryBroker + ":9092"
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", primaryBroker)
	if err != nil {
		return nil, fmt.Errorf("failed to dial kafka broker %s: %w", primaryBroker, err)
	}
	defer conn.Close()

	targetGroups := []string{"console-consumer", "connect-cluster", "schema-registry", "default-consumer-group"}
	if customGroup := os.Getenv("KAFKA_GROUP"); customGroup != "" {
		targetGroups = append([]string{customGroup}, targetGroups...)
	}

	// Build DescribeGroups request (API Key 15, Version 0)
	var reqBody bytes.Buffer
	// Request Header: API Key (int16), API Version (int16), Correlation ID (int32), Client ID (string)
	binary.Write(&reqBody, binary.BigEndian, int16(15)) // DescribeGroups
	binary.Write(&reqBody, binary.BigEndian, int16(0))  // v0
	binary.Write(&reqBody, binary.BigEndian, int32(1001))
	writeKafkaString(&reqBody, "x7-doctor")

	// DescribeGroups v0 body: Array of Group IDs (int32 count + string each)
	binary.Write(&reqBody, binary.BigEndian, int32(len(targetGroups)))
	for _, g := range targetGroups {
		writeKafkaString(&reqBody, g)
	}

	// Frame with message length
	var frame bytes.Buffer
	binary.Write(&frame, binary.BigEndian, int32(reqBody.Len()))
	frame.Write(reqBody.Bytes())

	if _, err := conn.Write(frame.Bytes()); err != nil {
		return nil, fmt.Errorf("write kafka describe-groups frame failed: %w", err)
	}

	// Read response frame
	var respLen int32
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		return nil, fmt.Errorf("read kafka response length failed: %w", err)
	}

	respBytes := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBytes); err != nil {
		return nil, fmt.Errorf("read kafka response body failed: %w", err)
	}

	r := bytes.NewReader(respBytes)
	var correlationID int32
	binary.Read(r, binary.BigEndian, &correlationID)

	var groupCount int32
	binary.Read(r, binary.BigEndian, &groupCount)

	results := make([]triage.DiagnosticResult, 0)

	for i := 0; i < int(groupCount); i++ {
		var errorCode int16
		binary.Read(r, binary.BigEndian, &errorCode)

		groupID, _ := readKafkaString(r)
		state, _ := readKafkaString(r)
		protocolType, _ := readKafkaString(r)
		protocol, _ := readKafkaString(r)

		var memberCount int32
		binary.Read(r, binary.BigEndian, &memberCount)

		var zombieMembers []string
		for m := 0; m < int(memberCount); m++ {
			memberID, _ := readKafkaString(r)
			clientID, _ := readKafkaString(r)
			clientHost, _ := readKafkaString(r)

			// Read member metadata byte array
			var metaLen int32
			binary.Read(r, binary.BigEndian, &metaLen)
			if metaLen > 0 {
				r.Seek(int64(metaLen), io.SeekCurrent)
			}
			// Read member assignment byte array
			var assignLen int32
			binary.Read(r, binary.BigEndian, &assignLen)
			if assignLen > 0 {
				r.Seek(int64(assignLen), io.SeekCurrent)
			}

			if strings.Contains(memberID, "unknown") || clientHost == "" {
				zombieMembers = append(zombieMembers, fmt.Sprintf("%s (%s)", memberID, clientID))
			}
		}

		target := fmt.Sprintf("Consumer Group '%s' (%s)", groupID, primaryBroker)

		if strings.EqualFold(state, "PreparingRebalance") {
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("infra-kafka-rebalance-%s", groupID),
				Subsystem:  triage.SubsystemInfra,
				Target:     target,
				Severity:   triage.SeverityDeadlock,
				Summary:    "Consumer group deadlocked in PreparingRebalance storm",
				Details:    fmt.Sprintf("Group '%s' is stuck in PreparingRebalance; protocol: %s/%s, members: %d. Consumers cannot read partition offsets.", groupID, protocolType, protocol, memberCount),
				Remediable: false,
			})
		} else if len(zombieMembers) > 0 {
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("infra-kafka-zombie-%s", groupID),
				Subsystem:  triage.SubsystemInfra,
				Target:     target,
				Severity:   triage.SeverityWarning,
				Summary:    fmt.Sprintf("Detected %d zombie members stalling consumer group", len(zombieMembers)),
				Details:    fmt.Sprintf("Zombie members: %s", strings.Join(zombieMembers, ", ")),
				Remediable: false,
			})
		}
	}

	if len(results) == 0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "infra-kafka-nominal",
			Subsystem:  triage.SubsystemInfra,
			Target:     fmt.Sprintf("Kafka (%s)", primaryBroker),
			Severity:   triage.SeverityOK,
			Summary:    "No PreparingRebalance storms or zombie group members detected",
			Remediable: false,
		})
	}

	return results, nil
}
