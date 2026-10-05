package backend

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// PostgresManager manages state locks in PostgreSQL backends using advisory locks.
type PostgresManager struct {
	ConnStr    string
	SchemaName string
	lastPID    int
	db         *sql.DB
}

// PostgresConfig holds parameters needed to initialize PostgresManager.
type PostgresConfig struct {
	ConnStr    string
	SchemaName string
}

// NewPostgresManager creates a new PostgreSQL lock manager.
func NewPostgresManager(cfg PostgresConfig) (*PostgresManager, error) {
	connStr := cfg.ConnStr
	if connStr == "" {
		if envConn := os.Getenv("PG_CONN_STR"); envConn != "" {
			connStr = envConn
		} else if envConn := os.Getenv("DATABASE_URL"); envConn != "" {
			connStr = envConn
		}
	}

	if connStr == "" {
		return nil, errors.New("conn_str is required for postgres backend")
	}

	schema := cfg.SchemaName
	if schema == "" {
		schema = "terraform_remote_state"
	}

	return &PostgresManager{
		ConnStr:    connStr,
		SchemaName: schema,
	}, nil
}

func (p *PostgresManager) Type() string {
	return "postgres"
}

func (p *PostgresManager) Target() string {
	return sanitizeConnStr(p.ConnStr)
}

// SetDB allows injecting an existing DB connection (useful for unit tests/mocking).
func (p *PostgresManager) SetDB(db *sql.DB) {
	p.db = db
}

// getDB returns an active DB connection or creates a new one.
func (p *PostgresManager) getDB() (*sql.DB, error) {
	if p.db != nil {
		return p.db, nil
	}
	db, err := sql.Open("postgres", p.ConnStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}
	db.SetMaxOpenConns(2)
	db.SetConnMaxLifetime(1 * time.Minute)
	return db, nil
}

func (p *PostgresManager) Inspect(ctx context.Context) (*LockInfo, error) {
	db, err := p.getDB()
	if err != nil {
		return nil, err
	}
	if p.db == nil {
		defer db.Close()
	}

	query := `
		SELECT
			a.pid,
			COALESCE(a.usename, ''),
			COALESCE(a.application_name, ''),
			COALESCE(a.client_addr::text, 'local'),
			COALESCE(a.state, 'unknown'),
			COALESCE(a.backend_start, NOW()),
			COALESCE(a.query_start, a.backend_start, NOW()),
			COALESCE(a.state_change, NOW()),
			l.locktype,
			l.mode,
			l.granted,
			COALESCE(l.classid, 0),
			COALESCE(l.objid, 0)
		FROM pg_locks l
		JOIN pg_stat_activity a ON l.pid = a.pid
		WHERE l.locktype = 'advisory'
		  AND a.pid <> pg_backend_pid()
		ORDER BY a.query_start ASC
		LIMIT 1;
	`

	row := db.QueryRowContext(ctx, query)

	var (
		pid          int
		usename      string
		appName      string
		clientAddr   string
		state        string
		backendStart time.Time
		queryStart   time.Time
		stateChange  time.Time
		locktype     string
		mode         string
		granted      bool
		classID      int64
		objID        int64
	)

	err = row.Scan(
		&pid,
		&usename,
		&appName,
		&clientAddr,
		&state,
		&backendStart,
		&queryStart,
		&stateChange,
		&locktype,
		&mode,
		&granted,
		&classID,
		&objID,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No advisory lock found
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query pg_locks/pg_stat_activity: %w", err)
	}

	p.lastPID = pid

	// Derive lock creation time
	created := queryStart
	if created.IsZero() {
		created = stateChange
	}
	if created.IsZero() {
		created = backendStart
	}

	lockID := fmt.Sprintf("pid-%d", pid)
	info := fmt.Sprintf("state: %s, app: %s, client: %s, advisory: (%d, %d), granted: %t",
		state, appName, clientAddr, classID, objID, granted)

	return &LockInfo{
		ID:          lockID,
		Operation:   fmt.Sprintf("advisory lock (%s)", mode),
		Info:        info,
		Who:         fmt.Sprintf("%s (pid %d)", usename, pid),
		Created:     created.UTC(),
		Path:        fmt.Sprintf("%s (advisory %d/%d)", p.SchemaName, classID, objID),
		BackendType: p.Type(),
		Target:      fmt.Sprintf("%s (pid %d)", p.Target(), pid),
		Extra: map[string]string{
			"pid":     strconv.Itoa(pid),
			"classid": strconv.FormatInt(classID, 10),
			"objid":   strconv.FormatInt(objID, 10),
		},
	}, nil
}

func (p *PostgresManager) Break(ctx context.Context, lockID string, force bool) error {
	db, err := p.getDB()
	if err != nil {
		return err
	}
	if p.db == nil {
		defer db.Close()
	}

	targetPID := p.lastPID
	if lockID != "" {
		cleanID := strings.TrimPrefix(lockID, "pid-")
		if parsed, err := strconv.Atoi(cleanID); err == nil && parsed > 0 {
			targetPID = parsed
		}
	}

	if targetPID <= 0 {
		// Attempt to inspect to find current stranded PID
		info, err := p.Inspect(ctx)
		if err != nil {
			return fmt.Errorf("failed to inspect postgres backend to determine PID: %w", err)
		}
		if info == nil {
			return errors.New("no active advisory lock found in PostgreSQL")
		}
		if p.lastPID <= 0 {
			return errors.New("unable to determine stranded PostgreSQL PID")
		}
		targetPID = p.lastPID
	}

	var terminated bool
	terminateQuery := "SELECT pg_terminate_backend($1);"
	err = db.QueryRowContext(ctx, terminateQuery, targetPID).Scan(&terminated)
	if err != nil {
		return fmt.Errorf("failed to execute pg_terminate_backend(%d): %w", targetPID, err)
	}

	if !terminated {
		return fmt.Errorf("pg_terminate_backend(%d) returned false (process may have already exited)", targetPID)
	}

	return nil
}

// sanitizeConnStr redacts credentials from PostgreSQL connection strings for safe display.
func sanitizeConnStr(raw string) string {
	if strings.HasPrefix(raw, "postgres://") || strings.HasPrefix(raw, "postgresql://") {
		u, err := url.Parse(raw)
		if err == nil {
			return u.Redacted()
		}
	}

	// Key-value style: user=... password=... host=...
	parts := strings.Fields(raw)
	var sanitized []string
	for _, part := range parts {
		if strings.HasPrefix(strings.ToLower(part), "password=") {
			sanitized = append(sanitized, "password=REDACTED")
		} else {
			sanitized = append(sanitized, part)
		}
	}
	return strings.Join(sanitized, " ")
}
