package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const desktopFixture = `{"installed":{
  "client_id":"fake-desktop.apps.googleusercontent.com",
  "client_secret":"synthetic-value-not-a-secret",
  "auth_uri":"https://wrong.example/auth",
  "token_uri":"https://wrong.example/token",
  "redirect_uris":["http://wrong.example/"],
  "scopes":["not-the-service-scope"]
}}`

func TestLoadDesktopClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth-client.json")
	_, err := LoadDesktopClient(path)
	if got := assertAuthCode(t, err, "oauth_client_not_configured"); got.Stage != StageClientConfig {
		t.Fatalf("missing client reported at %q", got.Stage)
	}
	if err := os.WriteFile(path, []byte(desktopFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadDesktopClient(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientID != "fake-desktop.apps.googleusercontent.com" || cfg.ClientSecret == "" || !slices.Equal(cfg.Scopes, []string{fstScope}) {
		t.Fatal("incorrect desktop client or service scopes")
	}
	if cfg.AuthURL != GoogleAuthURL || cfg.TokenURL != GoogleTokenURL || cfg.RedirectHost != "127.0.0.1" || cfg.CallbackPath != "/CALLBACK_AUTH" {
		t.Fatal("untrusted registration fields overrode the local OAuth policy")
	}
	for _, line := range []string{fmt.Sprintf("%v", cfg), fmt.Sprintf("%#v", cfg)} {
		if strings.Contains(line, cfg.ClientID) || strings.Contains(line, cfg.ClientSecret) {
			t.Fatal("configuration formatter exposed credentials")
		}
	}

	if err := os.Symlink(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	_, err = LoadDesktopClient(path + ".link")
	assertAuthCode(t, err, "insecure_oauth_client_file")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadDesktopClient(path)
	assertAuthCode(t, err, "insecure_oauth_client_file")
}

func TestRejectInvalidDesktopRegistration(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"web", strings.ReplaceAll(desktopFixture, `"installed"`, `"web"`)},
		{"mixed", `{"installed":{},"web":{}}`},
		{"malformed", `{"installed": "SYNTHETIC_PRIVATE_VALUE"`},
		{"bad-id", strings.ReplaceAll(desktopFixture, "apps.googleusercontent.com", "local.invalid")},
		{"trailing-data", desktopFixture + ` {}`},
		{"oversized", desktopFixture + strings.Repeat(" ", maxClientBytes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "oauth-client.json")
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadDesktopClient(path)
			got := assertAuthCode(t, err, "invalid_oauth_client_file")
			if got.Stage != StageClientConfig || strings.Contains(got.Message, "SYNTHETIC_PRIVATE_VALUE") {
				t.Fatalf("bad error report: %+v", got)
			}
		})
	}
}

func TestUnconfiguredManager(t *testing.T) {
	m := NewUnconfiguredManager()
	state, err := m.Status()
	if err != nil || state.LoggedIn || state.ClientConfigError != "oauth_client_not_configured" {
		t.Fatalf("unexpected unconfigured status: %+v, %v", state, err)
	}
	_, err = m.AccessToken(context.Background(), "")
	assertAuthCode(t, err, "oauth_client_not_configured")
	_, err = m.Login(context.Background(), 0, func(string) error {
		t.Fatal("unconfigured manager started login")
		return nil
	})
	assertAuthCode(t, err, "oauth_client_not_configured")
}
