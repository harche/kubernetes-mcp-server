package sandbox

import (
	"fmt"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	"k8s.io/utils/ptr"

	"github.com/containers/kubernetes-mcp-server/pkg/api"
	sandboxcfg "github.com/containers/kubernetes-mcp-server/pkg/sandbox"
)

// executorState caches the singleton executor across tool calls.
var executorState struct {
	mu       sync.Mutex
	executor sandboxcfg.Executor
}

// getExecutor returns the cached executor, creating one on first call based on config mode.
func getExecutor(params api.ToolHandlerParams) (sandboxcfg.Executor, error) {
	executorState.mu.Lock()
	defer executorState.mu.Unlock()

	if executorState.executor != nil {
		return executorState.executor, nil
	}

	cfg := sandboxcfg.GetConfig(params)
	switch cfg.EffectiveMode() {
	case sandboxcfg.ModeLocal:
		executorState.executor = sandboxcfg.NewLocalExecutor()
	case sandboxcfg.ModeRemote:
		executorState.executor = NewRemoteExecutor(cfg, params.KubernetesClient)
	default:
		return nil, fmt.Errorf("unsupported sandbox mode: %s", cfg.Mode)
	}
	return executorState.executor, nil
}

func initSandboxTools() []api.ServerTool {
	return []api.ServerTool{
		{Tool: api.Tool{
			Name:        "sandbox_exec",
			Description: "Execute a shell command or script in a sandbox environment. The command is run via bash -c, so pipes, redirects, and all shell features work. Supports local subprocess execution (default) and remote Kubernetes pod execution. Combine multiple commands into a single shell script to minimize round trips.",
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"command": {
						Type:        "string",
						Description: "Shell command or script to execute (run via bash -c). Supports pipes, redirects, and all bash features.",
					},
				},
				Required: []string{"command"},
			},
			Annotations: api.ToolAnnotations{
				Title:           "Sandbox: Exec",
				DestructiveHint: ptr.To(true),
				OpenWorldHint:   ptr.To(true),
			},
		}, Handler: sandboxExec, ClusterAware: ptr.To(false)},
	}
}

func sandboxExec(params api.ToolHandlerParams) (*api.ToolCallResult, error) {
	command, err := api.RequiredString(params, "command")
	if err != nil {
		return api.NewToolCallResult("", err), nil
	}

	executor, err := getExecutor(params)
	if err != nil {
		return api.NewToolCallResult("", err), nil
	}

	if err := executor.Ensure(params.Context); err != nil {
		return api.NewToolCallResult("", err), nil
	}

	result, execErr := executor.Exec(params.Context, command)
	if execErr != nil {
		return api.NewToolCallResult("", fmt.Errorf("sandbox exec failed: %w", execErr)), nil
	}
	if result == "" {
		result = "Command executed successfully (no output)"
	}
	return api.NewToolCallResult(result, nil), nil
}
