package sandbox

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
)

type LocalExecutorSuite struct {
	suite.Suite
}

func (s *LocalExecutorSuite) TestEnsure() {
	s.Run("returns nil", func() {
		exec := NewLocalExecutor()
		s.NoError(exec.Ensure(context.Background()))
	})
}

func (s *LocalExecutorSuite) TestExec() {
	s.Run("executes simple command", func() {
		exec := NewLocalExecutor()
		result, err := exec.Exec(context.Background(), "echo hello", nil)
		s.NoError(err)
		s.Contains(result, "hello")
	})

	s.Run("captures stderr", func() {
		exec := NewLocalExecutor()
		result, err := exec.Exec(context.Background(), "echo error >&2", nil)
		s.NoError(err)
		s.Contains(result, "error")
	})

	s.Run("returns error for non-zero exit code", func() {
		exec := NewLocalExecutor()
		_, err := exec.Exec(context.Background(), "exit 1", nil)
		s.Error(err)
		s.Contains(err.Error(), "exited with code 1")
	})

	s.Run("supports pipes and redirects", func() {
		exec := NewLocalExecutor()
		result, err := exec.Exec(context.Background(), "echo 'foo bar' | awk '{print $2}'", nil)
		s.NoError(err)
		s.Contains(result, "bar")
	})

	s.Run("respects context cancellation", func() {
		exec := NewLocalExecutor()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := exec.Exec(ctx, "sleep 10", nil)
		s.Error(err)
	})

	s.Run("injects kubeconfig when credentials provided", func() {
		exec := NewLocalExecutor()
		creds := &Credentials{
			Server:      "https://test-server:6443",
			BearerToken: "test-token-12345",
			Namespace:   "test-ns",
		}
		// The command checks that KUBECONFIG env var is set and the file exists
		result, err := exec.Exec(context.Background(), "test -f \"$KUBECONFIG\" && echo kubeconfig-exists", creds)
		s.NoError(err)
		s.Contains(result, "kubeconfig-exists")
	})
}

func TestLocalExecutor(t *testing.T) {
	suite.Run(t, new(LocalExecutorSuite))
}
