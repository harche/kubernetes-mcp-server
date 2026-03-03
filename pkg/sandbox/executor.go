package sandbox

import "context"

// Executor abstracts command execution for the sandbox toolset.
// Implementations exist for remote (Kubernetes pod) and local (subprocess) execution.
type Executor interface {
	// Ensure prepares the execution environment (e.g., creates a pod for remote mode).
	// It is idempotent; repeated calls reuse the existing environment if still valid.
	Ensure(ctx context.Context) error

	// Exec runs a shell command and returns the output.
	Exec(ctx context.Context, command string) (string, error)
}
