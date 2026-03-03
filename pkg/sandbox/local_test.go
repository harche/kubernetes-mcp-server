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
		result, err := exec.Exec(context.Background(), "echo hello")
		s.NoError(err)
		s.Contains(result, "hello")
	})

	s.Run("captures stderr", func() {
		exec := NewLocalExecutor()
		result, err := exec.Exec(context.Background(), "echo error >&2")
		s.NoError(err)
		s.Contains(result, "error")
	})

	s.Run("returns error for non-zero exit code", func() {
		exec := NewLocalExecutor()
		_, err := exec.Exec(context.Background(), "exit 1")
		s.Error(err)
		s.Contains(err.Error(), "exited with code 1")
	})

	s.Run("supports pipes and redirects", func() {
		exec := NewLocalExecutor()
		result, err := exec.Exec(context.Background(), "echo 'foo bar' | awk '{print $2}'")
		s.NoError(err)
		s.Contains(result, "bar")
	})

	s.Run("respects context cancellation", func() {
		exec := NewLocalExecutor()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := exec.Exec(ctx, "sleep 10")
		s.Error(err)
	})
}

func TestLocalExecutor(t *testing.T) {
	suite.Run(t, new(LocalExecutorSuite))
}
