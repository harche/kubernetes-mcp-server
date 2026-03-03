package sandbox

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"k8s.io/client-go/rest"
)

type CredentialsSuite struct {
	suite.Suite
}

func (s *CredentialsSuite) TestCredentialsFromRESTConfig() {
	s.Run("returns nil for nil config", func() {
		s.Nil(CredentialsFromRESTConfig(nil, "default"))
	})

	s.Run("extracts fields from rest config", func() {
		cfg := &rest.Config{
			Host:        "https://api.example.com:6443",
			BearerToken: "my-token",
			TLSClientConfig: rest.TLSClientConfig{
				CAData:   []byte("ca-cert-data"),
				Insecure: false,
			},
		}
		creds := CredentialsFromRESTConfig(cfg, "my-namespace")
		s.Equal("https://api.example.com:6443", creds.Server)
		s.Equal("my-token", creds.BearerToken)
		s.Equal([]byte("ca-cert-data"), creds.CACert)
		s.False(creds.Insecure)
		s.Equal("my-namespace", creds.Namespace)
	})
}

func (s *CredentialsSuite) TestKubeconfigYAML() {
	s.Run("generates valid kubeconfig without proxy", func() {
		creds := &Credentials{
			Server:      "https://api.example.com:6443",
			BearerToken: "test-token",
			CACert:      []byte("test-ca"),
			Namespace:   "default",
		}
		data, err := creds.KubeconfigYAML()
		s.NoError(err)
		s.Contains(string(data), "https://api.example.com:6443")
		s.Contains(string(data), "current-context: sandbox")
	})

	s.Run("points to proxy when denied resources configured", func() {
		creds := &Credentials{
			Server:      "https://api.example.com:6443",
			BearerToken: "test-token",
			Namespace:   "default",
			DeniedResources: []DeniedGVR{
				{Group: "", Version: "v1", Resource: "secrets"},
			},
		}
		data, err := creds.KubeconfigYAML()
		s.NoError(err)
		s.Contains(string(data), ProxyListenAddr)
		s.NotContains(string(data), "https://api.example.com:6443")
	})
}

func (s *CredentialsSuite) TestUseProxy() {
	s.Run("false when no denied resources", func() {
		creds := &Credentials{Server: "https://api.example.com:6443"}
		s.False(creds.UseProxy())
	})

	s.Run("true when denied resources present", func() {
		creds := &Credentials{
			Server:          "https://api.example.com:6443",
			DeniedResources: []DeniedGVR{{Group: "", Version: "v1", Resource: "secrets"}},
		}
		s.True(creds.UseProxy())
	})
}

func (s *CredentialsSuite) TestProxyConfigJSON() {
	s.Run("generates valid JSON", func() {
		creds := &Credentials{
			Server:      "https://api.example.com:6443",
			BearerToken: "test-token",
			CACert:      []byte("test-ca"),
			DeniedResources: []DeniedGVR{
				{Group: "", Version: "v1", Resource: "secrets"},
			},
		}
		data, err := creds.ProxyConfigJSON()
		s.NoError(err)
		s.Contains(string(data), `"upstream":"https://api.example.com:6443"`)
		s.Contains(string(data), `"token":"test-token"`)
		s.Contains(string(data), `"resource":"secrets"`)
	})
}

func TestCredentials(t *testing.T) {
	suite.Run(t, new(CredentialsSuite))
}
