package sandbox

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type ConfigSuite struct {
	suite.Suite
}

func (s *ConfigSuite) TestValidate() {
	s.Run("nil config returns error", func() {
		var c *Config
		s.Error(c.Validate())
	})

	s.Run("empty mode is valid", func() {
		c := DefaultConfig()
		c.Mode = ""
		s.NoError(c.Validate())
	})

	s.Run("local mode is valid", func() {
		c := DefaultConfig()
		c.Mode = ModeLocal
		s.NoError(c.Validate())
	})

	s.Run("remote mode is valid", func() {
		c := DefaultConfig()
		c.Mode = ModeRemote
		s.NoError(c.Validate())
	})

	s.Run("invalid mode returns error", func() {
		c := DefaultConfig()
		c.Mode = "invalid"
		s.Error(c.Validate())
	})
}

func (s *ConfigSuite) TestEffectiveMode() {
	s.Run("empty mode returns local", func() {
		c := &Config{}
		s.Equal(ModeLocal, c.EffectiveMode())
	})

	s.Run("explicit local returns local", func() {
		c := &Config{Mode: ModeLocal}
		s.Equal(ModeLocal, c.EffectiveMode())
	})

	s.Run("explicit remote returns remote", func() {
		c := &Config{Mode: ModeRemote}
		s.Equal(ModeRemote, c.EffectiveMode())
	})
}

func (s *ConfigSuite) TestDefaultConfig() {
	s.Run("has local mode", func() {
		c := DefaultConfig()
		s.Equal(ModeLocal, c.Mode)
	})
}

func TestConfig(t *testing.T) {
	suite.Run(t, new(ConfigSuite))
}
