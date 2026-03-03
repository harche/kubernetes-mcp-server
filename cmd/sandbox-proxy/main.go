// sandbox-proxy is a lightweight reverse proxy that enforces denied_resources
// policy for Kubernetes API traffic inside sandbox environments.
//
// It reads a JSON config file containing the upstream API server URL, bearer token,
// CA certificate, and denied resource rules. For each incoming request, it parses
// the URL to determine the Kubernetes resource being accessed and blocks requests
// to denied resources with a 403 Forbidden response.
//
// The config file is re-read on each request to support hot-reload when credentials
// or denied resources change between sandbox_exec calls.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
)

// ProxyConfig is the runtime configuration read from the config file.
type ProxyConfig struct {
	// Upstream is the real Kubernetes API server URL.
	Upstream string `json:"upstream"`
	// Token is the bearer token for authenticating to the upstream.
	Token string `json:"token,omitempty"`
	// ClientCert is the PEM-encoded client certificate for mTLS.
	ClientCert string `json:"client_cert,omitempty"`
	// ClientKey is the PEM-encoded client key for mTLS.
	ClientKey string `json:"client_key,omitempty"`
	// CACert is the PEM-encoded CA certificate for the upstream.
	CACert string `json:"ca_cert,omitempty"`
	// Insecure disables TLS certificate verification for the upstream.
	Insecure bool `json:"insecure"`
	// DeniedResources is the list of GVR patterns to block.
	DeniedResources []DeniedResource `json:"denied_resources"`
}

// DeniedResource represents a denied Kubernetes resource by GVR.
type DeniedResource struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

var (
	configPath string
	listenAddr string

	configMu    sync.Mutex
	cachedCfg   *ProxyConfig
	cachedModAt int64
)

func loadConfig() (*ProxyConfig, error) {
	configMu.Lock()
	defer configMu.Unlock()

	info, err := os.Stat(configPath)
	if err != nil {
		return nil, fmt.Errorf("config file stat: %w", err)
	}
	modAt := info.ModTime().UnixNano()
	if cachedCfg != nil && modAt == cachedModAt {
		return cachedCfg, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("config file read: %w", err)
	}
	var cfg ProxyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config file parse: %w", err)
	}
	cachedCfg = &cfg
	cachedModAt = modAt
	return &cfg, nil
}

// parseURLToGVR extracts the GroupVersionResource from a Kubernetes API URL path.
// This is the same logic as pkg/kubernetes/accesscontrol_round_tripper.go:parseURLToGVR.
func parseURLToGVR(path string) (group, version, resource string, ok bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")

	switch parts[0] {
	case "api":
		if len(parts) < 3 {
			return
		}
		version = parts[1]
		if parts[2] == "namespaces" && len(parts) > 4 {
			resource = parts[4]
		} else {
			resource = parts[2]
		}
	case "apis":
		if len(parts) < 4 {
			return
		}
		group = parts[1]
		version = parts[2]
		if parts[3] == "namespaces" && len(parts) > 5 {
			resource = parts[5]
		} else {
			resource = parts[3]
		}
	default:
		return
	}
	return group, version, resource, true
}

func isDenied(cfg *ProxyConfig, group, version, resource string) bool {
	for _, d := range cfg.DeniedResources {
		if d.Resource == "" {
			// Group+Version pair denied entirely
			if group == d.Group && version == d.Version {
				return true
			}
			continue
		}
		if group == d.Group && version == d.Version && resource == d.Resource {
			return true
		}
	}
	return false
}

func main() {
	flag.StringVar(&configPath, "config", "/tmp/.sandbox-proxy-config.json", "Path to proxy config file")
	flag.StringVar(&listenAddr, "listen", ":9443", "Address to listen on")
	flag.Parse()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg, err := loadConfig()
		if err != nil {
			http.Error(w, fmt.Sprintf("proxy config error: %v", err), http.StatusInternalServerError)
			return
		}

		// Check denied resources
		if g, v, res, ok := parseURLToGVR(r.URL.Path); ok {
			if isDenied(cfg, g, v, res) {
				http.Error(w, fmt.Sprintf("resource denied by policy: %s/%s %s", g, v, res), http.StatusForbidden)
				return
			}
		}

		// Forward to upstream
		upstream, err := url.Parse(cfg.Upstream)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid upstream URL: %v", err), http.StatusInternalServerError)
			return
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec // configurable per admin policy
		}
		if cfg.CACert != "" {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
				tlsConfig.RootCAs = pool
			}
		}
		if cfg.ClientCert != "" && cfg.ClientKey != "" {
			cert, certErr := tls.X509KeyPair([]byte(cfg.ClientCert), []byte(cfg.ClientKey))
			if certErr == nil {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}

		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = upstream.Scheme
				req.URL.Host = upstream.Host
				req.Host = upstream.Host
				if cfg.Token != "" {
					req.Header.Set("Authorization", "Bearer "+cfg.Token)
				}
			},
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
		proxy.ServeHTTP(w, r)
	})

	log.Printf("sandbox-proxy listening on %s, config: %s", listenAddr, configPath)
	if err := http.ListenAndServe(listenAddr, handler); err != nil { //nolint:gosec // localhost-only proxy
		log.Fatalf("proxy server error: %v", err)
	}
}
