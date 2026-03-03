package sandbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/containers/kubernetes-mcp-server/pkg/api"
	"github.com/containers/kubernetes-mcp-server/pkg/config"
)

const ToolsetName = "sandbox"

const (
	// ModeLocal executes commands as local subprocesses via bash.
	ModeLocal = "local"
	// ModeRemote executes commands in a Kubernetes sandbox pod.
	ModeRemote = "remote"
)

// Config holds sandbox toolset configuration.
type Config struct {
	// Mode selects the execution backend: "local" (subprocess) or "remote" (Kubernetes pod).
	// Defaults to "local".
	Mode string `toml:"mode,omitempty"`
	// Image is the container image for the sandbox pod (remote mode only).
	Image string `toml:"image,omitempty"`
	// Namespace is the default namespace to create sandbox pods in.
	Namespace string `toml:"namespace,omitempty"`
	// ServiceAccount is the name of the ServiceAccount to attach to sandbox pods.
	ServiceAccount string `toml:"service_account,omitempty"`
	// CPURequest is the CPU resource request for the sandbox pod.
	CPURequest string `toml:"cpu_request,omitempty"`
	// CPULimit is the CPU resource limit for the sandbox pod.
	CPULimit string `toml:"cpu_limit,omitempty"`
	// MemoryRequest is the memory resource request for the sandbox pod.
	MemoryRequest string `toml:"memory_request,omitempty"`
	// MemoryLimit is the memory resource limit for the sandbox pod.
	MemoryLimit string `toml:"memory_limit,omitempty"`
	// ReadyTimeoutSeconds is how long to wait for the sandbox pod to become ready.
	ReadyTimeoutSeconds int `toml:"ready_timeout_seconds,omitempty"`
}

var _ api.ExtendedConfig = (*Config)(nil)

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("sandbox config is nil")
	}
	switch c.Mode {
	case ModeLocal, ModeRemote, "":
		// valid
	default:
		return fmt.Errorf("invalid sandbox mode %q: must be %q or %q", c.Mode, ModeLocal, ModeRemote)
	}
	return nil
}

// EffectiveMode returns the configured mode, defaulting to ModeLocal if empty.
func (c *Config) EffectiveMode() string {
	if c.Mode == "" {
		return ModeLocal
	}
	return c.Mode
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Mode:                ModeLocal,
		Image:               "kube-shell-sandbox:latest",
		ServiceAccount:      "sandbox-shell",
		CPURequest:          "100m",
		CPULimit:            "500m",
		MemoryRequest:       "128Mi",
		MemoryLimit:         "512Mi",
		ReadyTimeoutSeconds: 120,
	}
}

// GetConfig extracts the sandbox Config from the ExtendedConfigProvider.
// Returns DefaultConfig() if no config is registered.
func GetConfig(provider api.ExtendedConfigProvider) *Config {
	if cfg, ok := provider.GetToolsetConfig(ToolsetName); ok {
		if sc, ok := cfg.(*Config); ok && sc != nil {
			return sc
		}
	}
	return DefaultConfig()
}

func sandboxToolsetParser(_ context.Context, primitive toml.Primitive, md toml.MetaData) (api.ExtendedConfig, error) {
	cfg := DefaultConfig()
	if err := md.PrimitiveDecode(primitive, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func init() {
	config.RegisterToolsetConfig(ToolsetName, sandboxToolsetParser)
}
