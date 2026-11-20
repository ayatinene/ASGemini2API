package auth

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
)

const (
	// fstScope is OAuthScope.Flexible, the only scope the packaged Stable IDE
	// requests when the FSTS branch is active (the shipped default).
	fstScope       = "https://www.googleapis.com/auth/flexible-api"
	aiCodeScope    = "https://www.googleapis.com/auth/aicode"
	maxClientBytes = 16 << 10
)

var desktopClientID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,191}\.apps\.googleusercontent\.com$`)

// LoadDesktopClient reads the deployment's own Google Desktop app registration.
// This does not establish that Google permits the client to request AiCode access.
func LoadDesktopClient(path string) (Config, error) {
	f, err := openPrivateClientFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, clientNotConfigured()
	}
	if err != nil {
		return Config{}, &Error{Code: "insecure_oauth_client_file", Stage: StageClientConfig, Message: "OAuth client file must be an owner-only readable regular file, not a symlink"}
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxClientBytes+1))
	if err != nil || len(raw) > maxClientBytes {
		return Config{}, invalidDesktopClient("OAuth client file is unreadable or too large")
	}
	var registration struct {
		Installed *struct {
			ID     string `json:"client_id"`
			Secret string `json:"client_secret"`
		} `json:"installed"`
		Web json.RawMessage `json:"web"`
	}
	if err := json.Unmarshal(raw, &registration); err != nil || registration.Installed == nil || registration.Web != nil {
		return Config{}, invalidDesktopClient("expected Google Desktop app registration JSON with one installed client")
	}
	id, secret := registration.Installed.ID, registration.Installed.Secret
	if !desktopClientID.MatchString(id) || secret == "" || len(secret) > 1024 || hasControlOrSpace(secret) {
		return Config{}, invalidDesktopClient("invalid Desktop app client credentials")
	}
	// Endpoints, callback host and service scope are not taken from external JSON.
	// The request shape mirrors GoogleLoginState.loginAndCreate: with FSTS enabled
	// the IDE requests OAuthScope.Flexible and nothing else.
	cfg := Config{
		ClientID: id, ClientSecret: secret,
		Scopes:       []string{fstScope},
		CallbackPath: "/CALLBACK_AUTH",
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, withStage(err, StageClientConfig)
	}
	return cfg, nil
}

func clientNotConfigured() *Error {
	return &Error{Code: "oauth_client_not_configured", Stage: StageClientConfig, Message: "configure the local OAuth Desktop client file (ASGEMINI_OAUTH_CLIENT_FILE)"}
}

func invalidDesktopClient(message string) *Error {
	return &Error{Code: "invalid_oauth_client_file", Stage: StageClientConfig, Message: message}
}
