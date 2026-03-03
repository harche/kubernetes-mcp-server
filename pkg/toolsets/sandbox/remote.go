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
	mu        sync.Mutex
	name      string
	namespace string
	ready     bool
	config    *sandboxcfg.Config
	client    api.KubernetesClient
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

func (r *RemoteExecutor) Exec(ctx context.Context, command string) (string, error) {
	r.mu.Lock()
	name, namespace := r.name, r.namespace
	r.mu.Unlock()

	core := kubernetes.NewCore(r.client)
	return core.SandboxExec(ctx, namespace, name, command)
}
