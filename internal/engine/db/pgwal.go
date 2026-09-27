package db

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/x7ssss/x7/pkg/triage"
)

// PGConfig holds connection parameters for PostgreSQL.
type PGConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Database string
}

// GetPGConfig retrieves PostgreSQL credentials from environment variables or DSN.
func GetPGConfig() *PGConfig {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("PG_DSN")
	}
	if dsn != "" {
		u, err := url.Parse(dsn)
		if err == nil {
			host := u.Hostname()
			port := u.Port()
			if port == "" {
				port = "5432"
			}
			user := u.User.Username()
			pass, _ := u.User.Password()
			dbName := strings.TrimPrefix(u.Path, "/")
			if dbName == "" {
				dbName = "postgres"
			}
			return &PGConfig{
				Host:     host,
				Port:     port,
				User:     user,
				Password: pass,
				Database: dbName,
			}
		}
	}

	host := os.Getenv("PGHOST")
	if host == "" {
		host = os.Getenv("POSTGRES_HOST")
	}
	if host == "" {
		return nil
	}

	port := os.Getenv("PGPORT")
	if port == "" {
		port = "5432"
	}
	user := os.Getenv("PGUSER")
	if user == "" {
		user = "postgres"
	}
	pass := os.Getenv("PGPASSWORD")
	dbName := os.Getenv("PGDATABASE")
	if dbName == "" {
		dbName = "postgres"
	}

	return &PGConfig{
		Host:     host,
		Port:     port,
		User:     user,
		Password: pass,
		Database: dbName,
	}
}

// ExecutePGQuery connects to PostgreSQL via pure Go wire protocol v3 and executes a simple query.
func ExecutePGQuery(ctx context.Context, cfg *PGConfig, query string) ([][]string, error) {
	addr := net.JoinHostPort(cfg.Host, cfg.Port)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	}

	// 1. Startup message
	var buf bytes.Buffer
	// Protocol version 3.0 (196608)
	binary.Write(&buf, binary.BigEndian, int32(196608))
	buf.WriteString("user\x00")
	buf.WriteString(cfg.User + "\x00")
	buf.WriteString("database\x00")
	buf.WriteString(cfg.Database + "\x00")
	buf.WriteString("\x00")

	// Packet length includes the 4 bytes of length itself
	totalLen := int32(buf.Len() + 4)
	var pkt bytes.Buffer
	binary.Write(&pkt, binary.BigEndian, totalLen)
	pkt.Write(buf.Bytes())

	if _, err := conn.Write(pkt.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to send startup packet: %w", err)
	}

	// 2. Auth negotiation
	for {
		var msgType [1]byte
		if _, err := io.ReadFull(conn, msgType[:]); err != nil {
			return nil, fmt.Errorf("read msg type failed: %w", err)
		}
		var msgLen int32
		if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
			return nil, fmt.Errorf("read msg length failed: %w", err)
		}
		bodyLen := int(msgLen) - 4
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, fmt.Errorf("read msg body failed: %w", err)
		}

		if msgType[0] == 'E' { // ErrorResponse
			return nil, fmt.Errorf("postgres error: %s", string(body))
		}
		if msgType[0] == 'R' { // Authentication
			if len(body) >= 4 {
				authType := binary.BigEndian.Uint32(body[:4])
				if authType == 0 {
					// AuthenticationOk
					continue
				} else if authType == 3 {
					// CleartextPassword
					var passPkt bytes.Buffer
					passPkt.WriteByte('p')
					binary.Write(&passPkt, binary.BigEndian, int32(len(cfg.Password)+5))
					passPkt.WriteString(cfg.Password + "\x00")
					if _, err := conn.Write(passPkt.Bytes()); err != nil {
						return nil, err
					}
				} else if authType == 5 {
					// MD5 Password
					salt := body[4:8]
					hash1 := md5.Sum([]byte(cfg.Password + cfg.User))
					hex1 := hex.EncodeToString(hash1[:])
					var hash2Input bytes.Buffer
					hash2Input.WriteString(hex1)
					hash2Input.Write(salt)
					hash2 := md5.Sum(hash2Input.Bytes())
					finalMD5 := "md5" + hex.EncodeToString(hash2[:])

					var passPkt bytes.Buffer
					passPkt.WriteByte('p')
					binary.Write(&passPkt, binary.BigEndian, int32(len(finalMD5)+5))
					passPkt.WriteString(finalMD5 + "\x00")
					if _, err := conn.Write(passPkt.Bytes()); err != nil {
						return nil, err
					}
				} else {
					return nil, fmt.Errorf("unsupported postgres auth type: %d", authType)
				}
			}
		}
		if msgType[0] == 'Z' { // ReadyForQuery
			break
		}
	}

	// 3. Send Simple Query ('Q')
	var qPkt bytes.Buffer
	qPkt.WriteByte('Q')
	binary.Write(&qPkt, binary.BigEndian, int32(len(query)+5))
	qPkt.WriteString(query + "\x00")
	if _, err := conn.Write(qPkt.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	// 4. Read query results
	var rows [][]string
	for {
		var msgType [1]byte
		if _, err := io.ReadFull(conn, msgType[:]); err != nil {
			return nil, fmt.Errorf("query read error: %w", err)
		}
		var msgLen int32
		if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
			return nil, fmt.Errorf("query length read error: %w", err)
		}
		bodyLen := int(msgLen) - 4
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, fmt.Errorf("query body read error: %w", err)
		}

		if msgType[0] == 'E' {
			return nil, fmt.Errorf("query error: %s", string(body))
		}
		if msgType[0] == 'D' { // DataRow
			buf := bytes.NewReader(body)
			var colCount int16
			binary.Read(buf, binary.BigEndian, &colCount)
			row := make([]string, colCount)
			for i := 0; i < int(colCount); i++ {
				var colLen int32
				binary.Read(buf, binary.BigEndian, &colLen)
				if colLen == -1 {
					row[i] = "NULL"
				} else {
					val := make([]byte, colLen)
					buf.Read(val)
					row[i] = string(val)
				}
			}
			rows = append(rows, row)
		}
		if msgType[0] == 'Z' { // ReadyForQuery
			break
		}
	}

	return rows, nil
}

// PGWalEngine audits PostgreSQL pg_wal disk capacity and catches lagging replication slots.
type PGWalEngine struct{}

func NewPGWalEngine() *PGWalEngine {
	return &PGWalEngine{}
}

func (e *PGWalEngine) Name() string {
	return "db-pgwal"
}

func (e *PGWalEngine) Subsystem() triage.Subsystem {
	return triage.SubsystemDB
}

func (e *PGWalEngine) Inspect(ctx context.Context) ([]triage.DiagnosticResult, error) {
	cfg := GetPGConfig()
	if cfg == nil {
		return []triage.DiagnosticResult{
			{
				ID:         "db-pgwal-unconfigured",
				Subsystem:  triage.SubsystemDB,
				Target:     "PostgreSQL WAL",
				Severity:   triage.SeverityOK,
				Summary:    "No PostgreSQL host configured via PGHOST or POSTGRES_DSN; skipped",
				Remediable: false,
			},
		}, nil
	}

	query := "SELECT slot_name, active, COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn), 0)::text FROM pg_replication_slots;"
	rows, err := ExecutePGQuery(ctx, cfg, query)
	if err != nil {
		return nil, fmt.Errorf("failed to audit pg_wal replication slots: %w", err)
	}

	results := make([]triage.DiagnosticResult, 0)

	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		slotName := row[0]
		active := row[1] == "t"
		lagBytes, _ := strconv.ParseInt(row[2], 10, 64)

		target := fmt.Sprintf("Postgres Slot '%s' (%s:%s)", slotName, cfg.Host, cfg.Port)
		lagMB := float64(lagBytes) / (1024 * 1024)

		if !active && lagBytes > 100*1024*1024 { // Inactive slot with >100MB lag
			sName := slotName
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("db-pgwal-inactive-%s", slotName),
				Subsystem:  triage.SubsystemDB,
				Target:     target,
				Severity:   triage.SeverityDeadlock,
				Summary:    fmt.Sprintf("Inactive replication slot retaining %.1f MB of pg_wal logs", lagMB),
				Details:    fmt.Sprintf("Replication slot '%s' is inactive and holding WAL segments, leading to pg_wal disk capacity exhaustion.", slotName),
				Remediable: true,
				RemediateFn: func(remCtx context.Context, dryRun bool) error {
					if dryRun {
						return nil
					}
					dropQuery := fmt.Sprintf("SELECT pg_drop_replication_slot('%s');", sName)
					_, dropErr := ExecutePGQuery(remCtx, cfg, dropQuery)
					return dropErr
				},
			})
		} else if lagBytes > 10*1024*1024*1024 { // Active or inactive slot lagging by >10GB
			results = append(results, triage.DiagnosticResult{
				ID:         fmt.Sprintf("db-pgwal-lag-%s", slotName),
				Subsystem:  triage.SubsystemDB,
				Target:     target,
				Severity:   triage.SeverityCritical,
				Summary:    fmt.Sprintf("Replication slot lagging significantly (%.2f GB)", lagMB/1024),
				Details:    fmt.Sprintf("Replication lag of %d bytes poses an immediate risk of pg_wal disk fill-up.", lagBytes),
				Remediable: false,
			})
		}
	}

	if len(results) == 0 {
		results = append(results, triage.DiagnosticResult{
			ID:         "db-pgwal-nominal",
			Subsystem:  triage.SubsystemDB,
			Target:     fmt.Sprintf("Postgres pg_wal (%s:%s)", cfg.Host, cfg.Port),
			Severity:   triage.SeverityOK,
			Summary:    "pg_wal replication slots and disk retention nominal",
			Remediable: false,
		})
	}

	return results, nil
}
