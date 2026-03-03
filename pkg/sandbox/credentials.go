package sandbox

import (
	"encoding/json"
	"fmt"
	"os"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	// ProxyListenAddr is the address the sandbox proxy listens on.
	ProxyListenAddr = "http://localhost:9443"
	// ProxyConfigPath is the config file path inside the sandbox.
	ProxyConfigPath = "/tmp/.sandbox-proxy-config.json"
	// SandboxKubeconfigPath is the kubeconfig path inside the sandbox.
	SandboxKubeconfigPath = "/tmp/.sandbox-kubeconfig"
)

// DeniedGVR represents a denied Kubernetes resource by group/version/resource.
type DeniedGVR struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

// Credentials contains the information needed to configure kubectl
// and the policy proxy inside a sandbox environment.
type Credentials struct {
	// Server is the Kubernetes API server URL.
	Server string
	// BearerToken is the authentication token for the target cluster.
	BearerToken string
	// ClientCert is the PEM-encoded client certificate for mTLS authentication.
	ClientCert []byte
	// ClientKey is the PEM-encoded client private key for mTLS authentication.
	ClientKey []byte
	// CACert is the PEM-encoded CA certificate for TLS verification.
	CACert []byte
	// Insecure disables TLS certificate verification.
	Insecure bool
	// Namespace is the default namespace for this context.
	Namespace string
	// DeniedResources lists resources that should be blocked by the proxy.
	// When non-empty, the proxy is used and kubeconfig points to the proxy.
	DeniedResources []DeniedGVR
}

// CredentialsFromRESTConfig extracts credentials from a rest.Config.
// Returns nil if the config is nil.
func CredentialsFromRESTConfig(restConfig *rest.Config, namespace string) *Credentials {
	if restConfig == nil {
		return nil
	}
	caCert := restConfig.TLSClientConfig.CAData
	if len(caCert) == 0 && restConfig.TLSClientConfig.CAFile != "" {
		if data, err := os.ReadFile(restConfig.TLSClientConfig.CAFile); err == nil {
			caCert = data
		}
	}
	clientCert := restConfig.TLSClientConfig.CertData
	if len(clientCert) == 0 && restConfig.TLSClientConfig.CertFile != "" {
		if data, err := os.ReadFile(restConfig.TLSClientConfig.CertFile); err == nil {
			clientCert = data
		}
	}
	clientKey := restConfig.TLSClientConfig.KeyData
	if len(clientKey) == 0 && restConfig.TLSClientConfig.KeyFile != "" {
		if data, err := os.ReadFile(restConfig.TLSClientConfig.KeyFile); err == nil {
			clientKey = data
		}
	}
	return &Credentials{
		Server:      restConfig.Host,
		BearerToken: restConfig.BearerToken,
		ClientCert:  clientCert,
		ClientKey:   clientKey,
		CACert:      caCert,
		Insecure:    restConfig.TLSClientConfig.Insecure,
		Namespace:   namespace,
	}
}

// UseProxy returns true if the sandbox proxy should be used.
func (c *Credentials) UseProxy() bool {
	return len(c.DeniedResources) > 0
}

// KubeconfigYAML generates a kubeconfig YAML.
// When UseProxy() is true, the kubeconfig points to the local proxy
// (no token — the proxy injects it). Otherwise, it points directly
// to the API server with the bearer token.
func (c *Credentials) KubeconfigYAML() ([]byte, error) {
	const (
		clusterName = "sandbox-target"
		userName    = "sandbox-user"
		contextName = "sandbox"
	)

	cluster := clientcmdapi.NewCluster()
	authInfo := clientcmdapi.NewAuthInfo()

	if c.UseProxy() {
		// Point kubectl at the local proxy (HTTP, no TLS, no token)
		cluster.Server = ProxyListenAddr
	} else {
		// Point kubectl directly at the API server
		cluster.Server = c.Server
		cluster.InsecureSkipTLSVerify = c.Insecure
		if len(c.CACert) > 0 {
			cluster.CertificateAuthorityData = c.CACert
		}
		if c.BearerToken != "" {
			authInfo.Token = c.BearerToken
		}
		if len(c.ClientCert) > 0 {
			authInfo.ClientCertificateData = c.ClientCert
		}
		if len(c.ClientKey) > 0 {
			authInfo.ClientKeyData = c.ClientKey
		}
	}

	ctx := clientcmdapi.NewContext()
	ctx.Cluster = clusterName
	ctx.AuthInfo = userName
	if c.Namespace != "" {
		ctx.Namespace = c.Namespace
	}

	cfg := clientcmdapi.NewConfig()
	cfg.Clusters[clusterName] = cluster
	cfg.AuthInfos[userName] = authInfo
	cfg.Contexts[contextName] = ctx
	cfg.CurrentContext = contextName

	data, err := clientcmd.Write(*cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize kubeconfig: %w", err)
	}
	return data, nil
}

// proxyConfig is the JSON config consumed by the sandbox-proxy binary.
type proxyConfig struct {
	Upstream        string      `json:"upstream"`
	Token           string      `json:"token,omitempty"`
	ClientCert      string      `json:"client_cert,omitempty"`
	ClientKey       string      `json:"client_key,omitempty"`
	CACert          string      `json:"ca_cert,omitempty"`
	Insecure        bool        `json:"insecure"`
	DeniedResources []DeniedGVR `json:"denied_resources"`
}

// ProxyConfigJSON generates the JSON config file content for the sandbox proxy.
func (c *Credentials) ProxyConfigJSON() ([]byte, error) {
	cfg := proxyConfig{
		Upstream:        c.Server,
		Token:           c.BearerToken,
		ClientCert:      string(c.ClientCert),
		ClientKey:       string(c.ClientKey),
		CACert:          string(c.CACert),
		Insecure:        c.Insecure,
		DeniedResources: c.DeniedResources,
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proxy config: %w", err)
	}
	return data, nil
}
