package management

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthenticateManagementKey_RepeatedFailuresDoNotBanClient(t *testing.T) {
	const secret = "test-secret"
	secretHash, errHash := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if errHash != nil {
		t.Fatalf("failed to hash management key: %v", errHash)
	}

	tests := []struct {
		name        string
		clientIP    string
		localClient bool
		handler     *Handler
	}{
		{
			name:        "localhost environment key",
			clientIP:    "127.0.0.1",
			localClient: true,
			handler:     &Handler{cfg: &config.Config{}, envSecret: secret},
		},
		{
			name:     "remote environment key",
			clientIP: "192.0.2.10",
			handler: &Handler{
				cfg: &config.Config{}, envSecret: secret, allowRemoteOverride: true,
			},
		},
		{
			name:     "remote configured key",
			clientIP: "192.0.2.10",
			handler: &Handler{cfg: &config.Config{
				RemoteManagement: config.RemoteManagement{AllowRemote: true, SecretKey: string(secretHash)},
			}},
		},
		{
			name:        "localhost local password",
			clientIP:    "127.0.0.1",
			localClient: true,
			handler: &Handler{
				cfg: &config.Config{}, envSecret: "env-secret", localPassword: secret,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for i := 0; i < 10; i++ {
				for _, failure := range []struct {
					key     string
					message string
				}{
					{key: "wrong-secret", message: "invalid management key"},
					{key: "", message: "missing management key"},
				} {
					allowed, statusCode, errMsg := test.handler.AuthenticateManagementKey(test.clientIP, test.localClient, failure.key)
					if allowed || statusCode != http.StatusUnauthorized || errMsg != failure.message {
						t.Fatalf("unexpected auth result at attempt %d: allowed=%t status=%d msg=%q", i+1, allowed, statusCode, errMsg)
					}
				}
			}

			allowed, statusCode, errMsg := test.handler.AuthenticateManagementKey(test.clientIP, test.localClient, secret)
			if !allowed || statusCode != 0 || errMsg != "" {
				t.Fatalf("expected correct key to work after repeated failures: allowed=%t status=%d msg=%q", allowed, statusCode, errMsg)
			}
		})
	}
}

func TestMiddlewareSetsSupportPluginHeader(t *testing.T) {

	h := &Handler{
		cfg:       &config.Config{},
		envSecret: "test-secret",
	}
	middleware := h.Middleware()

	t.Run("invalid key", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
		c.Request.RemoteAddr = "127.0.0.1:12345"
		c.Request.Header.Set("X-Management-Key", "wrong-secret")

		middleware(c)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		if got := rec.Header().Get("X-CPA-SUPPORT-PLUGIN"); got != pluginhost.SupportPluginHeaderValue() {
			t.Fatalf("X-CPA-SUPPORT-PLUGIN = %q, want %q", got, pluginhost.SupportPluginHeaderValue())
		}
	})

	t.Run("valid key", func(t *testing.T) {
		engine := gin.New()
		engine.GET("/v0/management/config", middleware, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Management-Key", "test-secret")
		engine.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if got := rec.Header().Get("X-CPA-SUPPORT-PLUGIN"); got != pluginhost.SupportPluginHeaderValue() {
			t.Fatalf("X-CPA-SUPPORT-PLUGIN = %q, want %q", got, pluginhost.SupportPluginHeaderValue())
		}
	})
}
