## Sandbox integration

The sandbox toolset provides a `sandbox_exec` tool that lets AI assistants execute shell commands and scripts. It supports two execution modes:

- **Local mode** (default) — Runs commands as subprocesses on the machine where the MCP server is running.
- **Remote mode** — Runs commands inside a dedicated Kubernetes pod using the [agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) controller.

### Enable the sandbox toolset

The sandbox toolset is not enabled by default. Enable it via the CLI flag or a TOML configuration file.

CLI:

```shell
kubernetes-mcp-server --toolsets core,sandbox
```

Config (TOML):

```toml
toolsets = ["core", "sandbox"]
```

### Local mode (default)

In local mode, commands are executed as subprocesses via `bash -c` on the host running the MCP server. No Kubernetes resources or additional setup are required.

```toml
toolsets = ["core", "sandbox"]

# Local mode is the default — no additional configuration needed.
# To be explicit:
[toolset_configs.sandbox]
mode = "local"
```

This is useful when:
- You want to run shell commands, scripts, or CLI tools on your local machine.
- You don't need isolation between the MCP server and command execution.
- You're running the MCP server locally (e.g., with Claude Code).

### Remote mode

In remote mode, commands are executed inside a Kubernetes pod managed by the [agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) controller. The pod is created on first use and reused across tool calls within a session.

```toml
toolsets = ["core", "sandbox"]

[toolset_configs.sandbox]
mode = "remote"
image = "kube-shell-sandbox:latest"
namespace = "default"
service_account = "sandbox-shell"
```

#### Prerequisites

- A Kubernetes cluster with the [agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) controller installed
- RBAC permissions for the MCP server to manage Sandbox CRs, pods, and ServiceAccounts
- A sandbox container image (see [Building the sandbox image](#building-the-sandbox-image))

#### Setup

Use the provided setup script to install the agent-sandbox controller and apply RBAC:

```shell
./deploy/setup.sh
```

This script:
1. Installs agent-sandbox CRDs and controller (default: v0.1.1)
2. Waits for the controller to be ready
3. Applies sandbox RBAC from `deploy/sandbox-rbac.yaml`

To install a specific version:

```shell
./deploy/setup.sh v0.1.1
```

#### RBAC

Two sets of RBAC rules are required (see `deploy/sandbox-rbac.yaml`):

**MCP server permissions** — The MCP server's ServiceAccount (or kubeconfig user) needs:
- `agents.x-k8s.io/sandboxes`: create, get, list, delete, patch
- `pods`, `pods/exec`, `serviceaccounts`: create, get, list, delete

**Sandbox pod permissions** — The sandbox pod's ServiceAccount (`sandbox-shell` by default) gets read-only access to common cluster resources (pods, deployments, configmaps, nodes, etc.). Adjust `deploy/sandbox-rbac.yaml` based on your security requirements.

#### Building the sandbox image

Build the sandbox container image using the provided Makefile target:

```shell
make sandbox-image
```

This builds an Alpine-based image with: bash, curl, wget, jq, yq, git, kubectl, openssl, and other common CLI tools.

### Configuration reference

All configuration options for the sandbox toolset:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `"local"` | Execution mode: `"local"` (subprocess) or `"remote"` (Kubernetes pod) |
| `image` | string | `"kube-shell-sandbox:latest"` | Container image for the sandbox pod (remote mode only) |
| `namespace` | string | `""` (server default) | Namespace to create sandbox pods in (remote mode only) |
| `service_account` | string | `"sandbox-shell"` | ServiceAccount for sandbox pods (remote mode only) |
| `cpu_request` | string | `"100m"` | CPU resource request (remote mode only) |
| `cpu_limit` | string | `"500m"` | CPU resource limit (remote mode only) |
| `memory_request` | string | `"128Mi"` | Memory resource request (remote mode only) |
| `memory_limit` | string | `"512Mi"` | Memory resource limit (remote mode only) |
| `ready_timeout_seconds` | int | `120` | Timeout waiting for sandbox pod readiness (remote mode only) |

### Available tools

#### `sandbox_exec`

Execute a shell command or script in the sandbox environment. Commands are run via `bash -c`, so pipes, redirects, and all shell features work.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `command` | string | yes | Shell command or script to execute |

**Example usage by an AI assistant:**

```
sandbox_exec(command="kubectl get pods -o json | jq '.items[].metadata.name'")
sandbox_exec(command="echo 'Hello from sandbox'")
```
