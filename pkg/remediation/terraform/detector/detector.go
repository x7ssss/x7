package detector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/x7ssss/x7/pkg/remediation/terraform/backend"
)

// DefaultStatePath is the standard location for Terraform's local backend record.
const DefaultStatePath = ".terraform/terraform.tfstate"

// BackendConfig holds parsed remote backend configuration.
type BackendConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// tfLocalState matches the JSON schema of .terraform/terraform.tfstate.
type tfLocalState struct {
	Version int `json:"version"`
	Backend struct {
		Type   string                 `json:"type"`
		Config map[string]interface{} `json:"config"`
	} `json:"backend"`
}

// ParseStateFile reads and parses .terraform/terraform.tfstate.
func ParseStateFile(path string) (*BackendConfig, error) {
	if path == "" {
		path = DefaultStatePath
	}

	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("terraform local state not found at %s: run 'terraform init' first or pass --state", cleanPath)
		}
		return nil, fmt.Errorf("failed to read terraform state file %s: %w", cleanPath, err)
	}

	var state tfLocalState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("invalid json in terraform state file %s: %w", cleanPath, err)
	}

	if state.Backend.Type == "" {
		return nil, fmt.Errorf("no backend configuration found in %s", cleanPath)
	}

	return &BackendConfig{
		Type:   strings.ToLower(state.Backend.Type),
		Config: state.Backend.Config,
	}, nil
}

// NewLockManager instantiates the appropriate backend.LockManager based on BackendConfig.
func NewLockManager(cfg *BackendConfig) (backend.LockManager, error) {
	if cfg == nil {
		return nil, errors.New("backend configuration is nil")
	}

	switch cfg.Type {
	case "s3":
		useLockfile := GetBool(cfg.Config, "use_lockfile")
		dynamoTable := GetString(cfg.Config, "dynamodb_table")
		bucket := GetString(cfg.Config, "bucket")
		key := GetString(cfg.Config, "key")
		region := GetString(cfg.Config, "region")
		endpoint := GetString(cfg.Config, "endpoint")
		if endpoint == "" {
			endpoint = GetString(cfg.Config, "s3_endpoint")
		}

		if useLockfile {
			return backend.NewS3NativeManager(backend.S3NativeConfig{
				Bucket:   bucket,
				Key:      key,
				Region:   region,
				Endpoint: endpoint,
			})
		}

		if dynamoTable != "" {
			ddbEndpoint := GetString(cfg.Config, "dynamodb_endpoint")
			if ddbEndpoint == "" {
				ddbEndpoint = endpoint
			}
			return backend.NewDynamoDBManager(backend.DynamoDBConfig{
				TableName: dynamoTable,
				Bucket:    bucket,
				Key:       key,
				Region:    region,
				Endpoint:  ddbEndpoint,
			})
		}

		return nil, errors.New("s3 backend configured without 'dynamodb_table' or 'use_lockfile = true'")

	case "azurerm":
		return backend.NewAzureManager(backend.AzureConfig{
			AccountName:   GetString(cfg.Config, "storage_account_name"),
			ContainerName: GetString(cfg.Config, "container_name"),
			BlobName:      GetString(cfg.Config, "key"),
			AccountKey:    GetString(cfg.Config, "access_key"),
			SASToken:      GetString(cfg.Config, "sas_token"),
			Endpoint:      GetString(cfg.Config, "endpoint"),
		})

	case "pg", "postgres":
		connStr := GetString(cfg.Config, "conn_str")
		if connStr == "" {
			connStr = GetString(cfg.Config, "connection_string")
		}
		schema := GetString(cfg.Config, "schema_name")
		return backend.NewPostgresManager(backend.PostgresConfig{
			ConnStr:    connStr,
			SchemaName: schema,
		})

	default:
		return nil, fmt.Errorf("unsupported remote backend type %q: supported types are s3, azurerm, postgres", cfg.Type)
	}
}

// DetectAndLoad reads the state file and initializes the corresponding LockManager.
func DetectAndLoad(statePath string) (backend.LockManager, *BackendConfig, error) {
	cfg, err := ParseStateFile(statePath)
	if err != nil {
		return nil, nil, err
	}

	mgr, err := NewLockManager(cfg)
	if err != nil {
		return nil, nil, err
	}

	return mgr, cfg, nil
}

// GetString extracts a string value from the backend config map.
func GetString(cfg map[string]interface{}, key string) string {
	if cfg == nil {
		return ""
	}
	val, ok := cfg[key]
	if !ok || val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
}

// GetBool extracts a boolean value from the backend config map.
func GetBool(cfg map[string]interface{}, key string) bool {
	if cfg == nil {
		return false
	}
	val, ok := cfg[key]
	if !ok || val == nil {
		return false
	}
	switch v := val.(type) {
	case bool:
		return v
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		return err == nil && b
	case float64:
		return v != 0
	case int:
		return v != 0
	default:
		return false
	}
}
