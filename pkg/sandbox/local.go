package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// LocalExecutor runs commands as local subprocesses via bash -c.
type LocalExecutor struct{}

var _ Executor = (*LocalExecutor)(nil)

// NewLocalExecutor creates a LocalExecutor.
func NewLocalExecutor() *LocalExecutor {
	return &LocalExecutor{}
}

func (l *LocalExecutor) Ensure(_ context.Context) error {
	return nil
}

func (l *LocalExecutor) Exec(ctx context.Context, command string) (string, error) {
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", command)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

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
