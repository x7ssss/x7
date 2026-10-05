package k8s

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// ClientConfig holds settings for initializing the Kubernetes client.
type ClientConfig struct {
	KubeconfigPath string
	ContextName    string
}

// NewClient creates a Kubernetes client and returns the resolved default namespace.
// It prioritizes explicit kubeconfig path, then KUBECONFIG env var, ~/.kube/config,
// and finally falls back to in-cluster config.
func NewClient(cfg ClientConfig) (kubernetes.Interface, string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cfg.KubeconfigPath != "" {
		loadingRules.ExplicitPath = cfg.KubeconfigPath
	} else if envPath := os.Getenv("KUBECONFIG"); envPath != "" {
		loadingRules.Precedence = filepath.SplitList(envPath)
	} else if home := homedir.HomeDir(); home != "" {
		defaultKubeconfig := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(defaultKubeconfig); err == nil {
			loadingRules.ExplicitPath = defaultKubeconfig
		}
	}

	configOverrides := &clientcmd.ConfigOverrides{}
	if cfg.ContextName != "" {
		configOverrides.CurrentContext = cfg.ContextName
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	rawRestConfig, err := clientConfig.ClientConfig()
	if err != nil {
		// Attempt in-cluster config fallback if loading external kubeconfig fails
		inClusterConfig, inClusterErr := rest.InClusterConfig()
		if inClusterErr != nil {
			return nil, "", fmt.Errorf("failed to load kubeconfig (%v) and in-cluster config (%v)", err, inClusterErr)
		}
		clientset, err := kubernetes.NewForConfig(inClusterConfig)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create in-cluster client: %w", err)
		}
		// Read namespace from in-cluster serviceaccount file if present
		inClusterNS := "default"
		if nsBytes, readErr := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); readErr == nil {
			if trimmed := string(nsBytes); trimmed != "" {
				inClusterNS = trimmed
			}
		}
		return clientset, inClusterNS, nil
	}

	clientset, err := kubernetes.NewForConfig(rawRestConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	defaultNamespace, _, err := clientConfig.Namespace()
	if err != nil || defaultNamespace == "" {
		defaultNamespace = "default"
	}

	return clientset, defaultNamespace, nil
}
