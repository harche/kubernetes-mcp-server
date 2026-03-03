package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// LocalExecutor runs commands as local subprocesses via bash -c.
type LocalExecutor struct {
	mu             sync.Mutex
	proxyCmd       *exec.Cmd
	workDir        string // persistent temp directory for config files
	proxyConfigPath string
	kubeconfigPath  string
}

var _ Executor = (*LocalExecutor)(nil)

// NewLocalExecutor creates a LocalExecutor.
func NewLocalExecutor() *LocalExecutor {
	return &LocalExecutor{}
}

func (l *LocalExecutor) Ensure(_ context.Context) error {
	return nil
}

// ensureWorkDir creates a persistent temp directory for sandbox config files.
func (l *LocalExecutor) ensureWorkDir() error {
	if l.workDir != "" {
		return nil
	}
	dir, err := os.MkdirTemp("", "sandbox-local-*")
	if err != nil {
		return fmt.Errorf("failed to create sandbox work directory: %w", err)
	}
	l.workDir = dir
	l.kubeconfigPath = filepath.Join(dir, "kubeconfig")
	l.proxyConfigPath = filepath.Join(dir, "proxy-config.json")
	return nil
}

func (l *LocalExecutor) Exec(ctx context.Context, command string, creds *Credentials) (string, error) {
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", command)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if creds != nil {
		if err := l.ensureWorkDir(); err != nil {
			return "", err
		}

		kubeconfigData, err := creds.KubeconfigYAML()
		if err != nil {
			return "", fmt.Errorf("failed to generate kubeconfig: %w", err)
		}
		if err := os.WriteFile(l.kubeconfigPath, kubeconfigData, 0600); err != nil {
			return "", fmt.Errorf("failed to write kubeconfig: %w", err)
		}

		if creds.UseProxy() {
			proxyConfigData, err := creds.ProxyConfigJSON()
			if err != nil {
				return "", fmt.Errorf("failed to generate proxy config: %w", err)
			}
			if err := os.WriteFile(l.proxyConfigPath, proxyConfigData, 0600); err != nil {
				return "", fmt.Errorf("failed to write proxy config: %w", err)
			}
			if err := l.ensureProxy(); err != nil {
				return "", fmt.Errorf("failed to start proxy: %w", err)
			}
		}

		cmd.Env = append(os.Environ(), "KUBECONFIG="+l.kubeconfigPath)
	}

	err := cmd.Run()
	if stderr.Len() > 0 {
		if stdout.Len() > 0 {
			stdout.WriteByte('\n')
		}
		stdout.Write(stderr.Bytes())
	}
	output := stdout.String()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return output, fmt.Errorf("command exited with code %d: %w", exitErr.ExitCode(), exitErr)
		}
		return output, fmt.Errorf("command execution failed: %w", err)
	}

	return output, nil
}

// ensureProxy starts the sandbox-proxy if not already running.
func (l *LocalExecutor) ensureProxy() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check if proxy is already running
	if l.proxyCmd != nil && l.proxyCmd.Process != nil {
		// Check if process is still alive
		if err := l.proxyCmd.Process.Signal(nil); err == nil {
			return nil // still running, config file was already updated
		}
		l.proxyCmd = nil
	}

	proxyBin, err := exec.LookPath("sandbox-proxy")
	if err != nil {
		return fmt.Errorf("sandbox-proxy binary not found: %w", err)
	}

	cmd := exec.Command(proxyBin, "--config", l.proxyConfigPath)
	cmd.Stdout = os.Stderr // proxy logs go to stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start sandbox-proxy: %w", err)
	}
	l.proxyCmd = cmd

	// Wait briefly for the proxy to be ready
	time.Sleep(200 * time.Millisecond)
	return nil
}
