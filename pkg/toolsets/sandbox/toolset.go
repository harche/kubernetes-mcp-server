package sandbox

import (
	"github.com/containers/kubernetes-mcp-server/pkg/api"
	_ "github.com/containers/kubernetes-mcp-server/pkg/sandbox" // register toolset config parser
	"github.com/containers/kubernetes-mcp-server/pkg/toolsets"
)

type Toolset struct{}

var _ api.Toolset = (*Toolset)(nil)

func (t *Toolset) GetName() string {
	return "sandbox"
}

func (t *Toolset) GetDescription() string {
	return "Shell sandbox for executing commands (bash, scripts) locally or in a dedicated Kubernetes pod"
}

func (t *Toolset) GetTools(_ api.Openshift) []api.ServerTool {
	return initSandboxTools()
}

func (t *Toolset) GetPrompts() []api.ServerPrompt {
	return nil
}

func init() {
	toolsets.Register(&Toolset{})
}
