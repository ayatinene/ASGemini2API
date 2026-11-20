package settings

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeBounds(t *testing.T) {
	t.Setenv("ASGEMINI_UNARY_TIMEOUT", "15s")
	t.Setenv("ASGEMINI_MAX_IN_FLIGHT", "2")
	t.Setenv("ASGEMINI_OAUTH_CLIENT_FILE", "")
	c, err := FromEnv("/private/state", "/local/inputs")
	if err != nil {
		t.Fatal(err)
	}
	if c.UnaryTimeout != 15*time.Second || c.MaxInFlight != 2 || c.OAuthClientFile != "/local/inputs/oauth-client.json" {
		t.Fatalf("unexpected runtime configuration: %+v", c)
	}
	t.Setenv("ASGEMINI_OAUTH_CLIENT_FILE", "/private/registration.json")
	if c, err := FromEnv("/private/state", "/local/inputs"); err != nil || c.OAuthClientFile != "/private/registration.json" {
		t.Fatalf("expected OAuth client file override: %+v, %v", c, err)
	}
	t.Setenv("ASGEMINI_UNARY_TIMEOUT", "15")
	if _, err := FromEnv("/private/state", "/local/inputs"); err == nil {
		t.Fatal("unitless duration should be rejected")
	}
}

func TestRuntimeKeyFiles(t *testing.T) {
	const api = "example-api-secret-not-for-use"
	const admin = "example-admin-secret-not-for-use"
	t.Setenv("ASGEMINI_API_KEY", "")
	t.Setenv("ASGEMINI_ADMIN_KEY", admin)
	t.Setenv("ASGEMINI_ADMIN_KEY_FILE", "")
	path := filepath.Join(t.TempDir(), "api_key")
	if err := os.WriteFile(path, []byte(api+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ASGEMINI_API_KEY_FILE", path)
	keys, err := LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	if keys.API != sha256.Sum256([]byte(api)) || keys.Admin != sha256.Sum256([]byte(admin)) {
		t.Fatal("wrong API or admin digest")
	}
	t.Setenv("ASGEMINI_ADMIN_KEY", api)
	if _, err := LoadKeys(); err == nil {
		t.Fatal("API/admin key reuse should be rejected")
	}
	t.Setenv("ASGEMINI_API_KEY", api)
	if _, err := LoadKeys(); err == nil {
		t.Fatal("ambiguous file and environment key should be rejected")
	}
}
