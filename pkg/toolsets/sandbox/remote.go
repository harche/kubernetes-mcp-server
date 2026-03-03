package sandbox

import (
	"context"
	"fmt"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"

	"github.com/containers/kubernetes-mcp-server/pkg/api"
	"github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	sandboxcfg "github.com/containers/kubernetes-mcp-server/pkg/sandbox"
)

var _ sandboxcfg.Executor = (*RemoteExecutor)(nil)

// RemoteExecutor runs commands in a Kubernetes sandbox pod.
type RemoteExecutor struct {
	mu           sync.Mutex
	name         string
	namespace    string
	ready        bool
	proxyStarted bool
	config       *sandboxcfg.Config
	client       api.KubernetesClient
}

// NewRemoteExecutor creates a RemoteExecutor with the given config and Kubernetes client.
func NewRemoteExecutor(cfg *sandboxcfg.Config, client api.KubernetesClient) *RemoteExecutor {
	return &RemoteExecutor{
		config: cfg,
		client: client,
	}
}

func (r *RemoteExecutor) Ensure(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	core := kubernetes.NewCore(r.client)

	// If we have a sandbox, check it's still running
	if r.ready && r.name != "" {
		pod, err := core.SandboxStatus(ctx, r.namespace, r.name)
		if err == nil && pod.Status.Phase == v1.PodRunning {
			return nil
		}
		r.ready = false
		r.proxyStarted = false
	}

	// Create a new sandbox
	name := kubernetes.SandboxDefaultName()
	namespace := r.config.Namespace
	opts := kubernetes.SandboxOptions{
		Name:               name,
		Namespace:          namespace,
		Image:              r.config.Image,
		ServiceAccountName: r.config.ServiceAccount,
		CPURequest:         r.config.CPURequest,
		CPULimit:           r.config.CPULimit,
		MemoryRequest:      r.config.MemoryRequest,
		MemoryLimit:        r.config.MemoryLimit,
	}

	if _, err := core.SandboxCreate(ctx, opts); err != nil {
		return fmt.Errorf("failed to create sandbox: %w", err)
	}

	timeout := time.Duration(r.config.ReadyTimeoutSeconds) * time.Second
	if err := core.SandboxWaitReady(ctx, namespace, name, timeout); err != nil {
		return fmt.Errorf("sandbox created but not ready: %w", err)
	}

	r.name = name
	r.namespace = core.NamespaceOrDefault(namespace)
	r.ready = true
	return nil
}

func (r *RemoteExecutor) Exec(ctx context.Context, command string, creds *sandboxcfg.Credentials) (string, error) {
	r.mu.Lock()
	name, namespace := r.name, r.namespace
	r.mu.Unlock()

	core := kubernetes.NewCore(r.client)

	if creds != nil {
		// Write kubeconfig into the pod
		kubeconfigData, err := creds.KubeconfigYAML()
		if err != nil {
			return "", fmt.Errorf("failed to generate kubeconfig: %w", err)
		}
		writeKubeconfig := fmt.Sprintf(
			"cat > %s << 'KUBECONFIG_EOF'\n%s\nKUBECONFIG_EOF\nchmod 600 %s",
			sandboxcfg.SandboxKubeconfigPath, string(kubeconfigData), sandboxcfg.SandboxKubeconfigPath,
		)
		if _, err := core.SandboxExec(ctx, namespace, name, writeKubeconfig); err != nil {
			return "", fmt.Errorf("failed to inject kubeconfig into sandbox: %w", err)
		}

		// If proxy is needed, write config and start proxy
		if creds.UseProxy() {
			proxyConfigData, err := creds.ProxyConfigJSON()
			if err != nil {
				return "", fmt.Errorf("failed to generate proxy config: %w", err)
			}
			writeProxyConfig := fmt.Sprintf(
				"cat > %s << 'PROXY_CONFIG_EOF'\n%s\nPROXY_CONFIG_EOF\nchmod 600 %s",
				sandboxcfg.ProxyConfigPath, string(proxyConfigData), sandboxcfg.ProxyConfigPath,
			)
			if _, err := core.SandboxExec(ctx, namespace, name, writeProxyConfig); err != nil {
				return "", fmt.Errorf("failed to inject proxy config into sandbox: %w", err)
			}

			if err := r.ensureProxy(ctx, core, namespace, name); err != nil {
				return "", fmt.Errorf("failed to start proxy in sandbox: %w", err)
			}
		}

		command = fmt.Sprintf("export KUBECONFIG=%s\n%s", sandboxcfg.SandboxKubeconfigPath, command)
	}

	return core.SandboxExec(ctx, namespace, name, command)
}

// ensureProxy starts the sandbox-proxy process inside the pod if not already running.
func (r *RemoteExecutor) ensureProxy(ctx context.Context, core *kubernetes.Core, namespace, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.proxyStarted {
		// Check if proxy is still running
		output, err := core.SandboxExec(ctx, namespace, name, "pgrep -f sandbox-proxy || true")
		if err == nil && output != "" {
			return nil // still running
		}
		r.proxyStarted = false
	}

	// Start proxy in background
	startCmd := fmt.Sprintf("sandbox-proxy --config %s &", sandboxcfg.ProxyConfigPath)
	if _, err := core.SandboxExec(ctx, namespace, name, startCmd); err != nil {
		return fmt.Errorf("failed to start sandbox-proxy: %w", err)
	}

	// Brief wait for proxy to bind
	time.Sleep(200 * time.Millisecond)
	r.proxyStarted = true
	return nil
}
