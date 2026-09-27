package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	_ "k8s.io/client-go/pkg/version"
	"k8s.io/apimachinery/pkg/types"
)

// GlobalKubeconfigPath holds an optional explicit path to a kubeconfig file.
var GlobalKubeconfigPath string

// kubeConfigFile parses standard Kubernetes kubeconfig YAML structure.
type kubeConfigFile struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string `yaml:"token"`
			ClientCertificate     string `yaml:"client-certificate"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKey             string `yaml:"client-key"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// K8sClient provides a high-performance zero-overhead client for the Kubernetes API.
type K8sClient struct {
	BaseURL     string
	BearerToken string
	HTTPClient  *http.Client
}

// GetK8sClient initializes a K8sClient from kubeconfig files or in-cluster service account.
func GetK8sClient() (*K8sClient, error) {
	configPath := GlobalKubeconfigPath
	if configPath == "" {
		configPath = os.Getenv("KUBECONFIG")
	}
	if configPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			defaultPath := filepath.Join(home, ".kube", "config")
			if _, statErr := os.Stat(defaultPath); statErr == nil {
				configPath = defaultPath
			}
		}
	}

	if configPath != "" {
		client, err := buildClientFromKubeconfig(configPath)
		if err == nil {
			return client, nil
		}
	}

	// Try in-cluster service account
	inClusterClient, err := buildInClusterClient()
	if err == nil {
		return inClusterClient, nil
	}

	return nil, fmt.Errorf("kubernetes configuration not found: %w", err)
}

func buildClientFromKubeconfig(path string) (*K8sClient, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var kc kubeConfigFile
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}

	targetCtxName := kc.CurrentContext
	var clusterName, userName string
	for _, ctx := range kc.Contexts {
		if ctx.Name == targetCtxName || targetCtxName == "" {
			clusterName = ctx.Context.Cluster
			userName = ctx.Context.User
			break
		}
	}

	var server string
	var caData []byte
	var insecure bool
	for _, c := range kc.Clusters {
		if c.Name == clusterName || clusterName == "" {
			server = strings.TrimRight(c.Cluster.Server, "/")
			insecure = c.Cluster.InsecureSkipTLSVerify
			if c.Cluster.CertificateAuthorityData != "" {
				caData, _ = base64.StdEncoding.DecodeString(c.Cluster.CertificateAuthorityData)
			} else if c.Cluster.CertificateAuthority != "" {
				caPath := c.Cluster.CertificateAuthority
				if !filepath.IsAbs(caPath) {
					caPath = filepath.Join(filepath.Dir(path), caPath)
				}
				caData, _ = os.ReadFile(caPath)
			}
			break
		}
	}

	if server == "" {
		return nil, fmt.Errorf("no server cluster endpoint found in kubeconfig")
	}

	var token string
	var certData, keyData []byte
	for _, u := range kc.Users {
		if u.Name == userName || userName == "" {
			token = u.User.Token
			if u.User.ClientCertificateData != "" {
				certData, _ = base64.StdEncoding.DecodeString(u.User.ClientCertificateData)
			} else if u.User.ClientCertificate != "" {
				certPath := u.User.ClientCertificate
				if !filepath.IsAbs(certPath) {
					certPath = filepath.Join(filepath.Dir(path), certPath)
				}
				certData, _ = os.ReadFile(certPath)
			}
			if u.User.ClientKeyData != "" {
				keyData, _ = base64.StdEncoding.DecodeString(u.User.ClientKeyData)
			} else if u.User.ClientKey != "" {
				keyPath := u.User.ClientKey
				if !filepath.IsAbs(keyPath) {
					keyPath = filepath.Join(filepath.Dir(path), keyPath)
				}
				keyData, _ = os.ReadFile(keyPath)
			}
			break
		}
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
	}

	if len(caData) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caData)
		tlsConfig.RootCAs = pool
	}

	if len(certData) > 0 && len(keyData) > 0 {
		cert, certErr := tls.X509KeyPair(certData, keyData)
		if certErr == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	return &K8sClient{
		BaseURL:     server,
		BearerToken: token,
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     tlsConfig,
				DisableKeepAlives:   false,
				MaxIdleConnsPerHost: 10,
			},
			Timeout: 10 * time.Second,
		},
	}, nil
}

func buildInClusterClient() (*K8sClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("not running in a kubernetes pod")
	}

	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, err
	}

	caBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caBytes)

	tlsConfig := &tls.Config{
		RootCAs: pool,
	}

	return &K8sClient{
		BaseURL:     fmt.Sprintf("https://%s:%s", host, port),
		BearerToken: strings.TrimSpace(string(tokenBytes)),
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
			Timeout: 10 * time.Second,
		},
	}, nil
}

// Get executes a GET request against the Kubernetes API.
func (c *K8sClient) Get(ctx context.Context, path string) ([]byte, error) {
	reqURL := c.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kubernetes API returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// Patch executes a PATCH request against the Kubernetes API.
func (c *K8sClient) Patch(ctx context.Context, path string, patchType string, data []byte) ([]byte, error) {
	reqURL := c.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, reqURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	if patchType == "" {
		patchType = "application/strategic-merge-patch+json"
	}
	req.Header.Set("Content-Type", patchType)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kubernetes patch API returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// Delete executes a DELETE request against the Kubernetes API.
func (c *K8sClient) Delete(ctx context.Context, path string) error {
	reqURL := c.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, nil)
	if err != nil {
		return err
	}
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("kubernetes delete API returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ObjectMeta captures standard Kubernetes object metadata.
type ObjectMeta struct {
	Name              string            `json:"name,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               types.UID         `json:"uid,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	Generation        int64             `json:"generation,omitempty"`
	CreationTimestamp string            `json:"creationTimestamp,omitempty"`
	DeletionTimestamp *string           `json:"deletionTimestamp,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	Finalizers        []string          `json:"finalizers,omitempty"`
}

type K8sNamespace struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Finalizers []string `json:"finalizers"`
	} `json:"spec"`
	Status struct {
		Phase      string `json:"phase"`
		Conditions []struct {
			Type    string `json:"type"`
			Status  string `json:"status"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"conditions"`
	} `json:"status"`
}

type K8sNamespaceList struct {
	Items []K8sNamespace `json:"items"`
}

type K8sAPIService struct {
	Metadata ObjectMeta `json:"metadata"`
	Status   struct {
		Conditions []struct {
			Type    string `json:"type"`
			Status  string `json:"status"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"conditions"`
	} `json:"status"`
}

type K8sAPIServiceList struct {
	Items []K8sAPIService `json:"items"`
}

type K8sSecret struct {
	Metadata ObjectMeta `json:"metadata"`
}

type K8sSecretList struct {
	Items []K8sSecret `json:"items"`
}

type K8sCRD struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Group string `json:"group"`
		Names struct {
			Plural string `json:"plural"`
		} `json:"names"`
		Versions []struct {
			Name string `json:"name"`
		} `json:"versions"`
	} `json:"spec"`
}

type K8sCRDList struct {
	Items []K8sCRD `json:"items"`
}

type K8sCustomResourceList struct {
	Items []struct {
		Metadata ObjectMeta `json:"metadata"`
	} `json:"items"`
}

type K8sDeployment struct {
	Metadata ObjectMeta `json:"metadata"`
	Status   struct {
		ObservedGeneration int64 `json:"observedGeneration"`
	} `json:"status"`
}

type K8sDeploymentList struct {
	Items []K8sDeployment `json:"items"`
}

var _ = json.Marshal
