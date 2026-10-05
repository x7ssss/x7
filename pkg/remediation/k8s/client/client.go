package client

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

// Clients holds all required Kubernetes client interfaces.
type Clients struct {
	KubeClient       kubernetes.Interface
	DynamicClient    dynamic.Interface
	DiscoveryClient  discovery.DiscoveryInterface
	AggregatorClient aggregatorclient.Interface
	Config           *rest.Config
}

// NewClients resolves the Kubernetes configuration and instantiates all typed, dynamic, and aggregator clients.
func NewClients(kubeconfigPath string) (*Clients, error) {
	config, err := buildConfig(kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubernetes configuration: %w", err)
	}

	// Elevate QPS and Burst for exhaustive cluster scanning
	config.QPS = 50.0
	config.Burst = 100

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes core client: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	aggregatorClient, err := aggregatorclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kube-aggregator client: %w", err)
	}

	discoveryClient := kubeClient.Discovery()

	return &Clients{
		KubeClient:       kubeClient,
		DynamicClient:    dynamicClient,
		DiscoveryClient:  discoveryClient,
		AggregatorClient: aggregatorClient,
		Config:           config,
	}, nil
}

func buildConfig(kubeconfigPath string) (*rest.Config, error) {
	// 1. Explicit CLI flag
	if kubeconfigPath != "" {
		if _, err := os.Stat(kubeconfigPath); err == nil {
			return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		}
		return nil, fmt.Errorf("specified kubeconfig path %q not found", kubeconfigPath)
	}

	// 2. KUBECONFIG environment variable
	if envKubeconfig := os.Getenv("KUBECONFIG"); envKubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", envKubeconfig)
	}

	// 3. In-cluster configuration (ServiceAccount tokens in pods)
	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}

	// 4. Default user home directory ~/.kube/config
	if home := homedir.HomeDir(); home != "" {
		defaultPath := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(defaultPath); err == nil {
			return clientcmd.BuildConfigFromFlags("", defaultPath)
		}
	}

	return nil, fmt.Errorf("no kubernetes configuration could be found (checked --kubeconfig flag, KUBECONFIG env, in-cluster config, and ~/.kube/config)")
}
