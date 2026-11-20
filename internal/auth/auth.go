package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	GoogleAuthURL     = "https://accounts.google.com/o/oauth2/auth"
	GoogleTokenURL    = "https://oauth2.googleapis.com/token"
	GoogleUserinfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	GoogleRevokeURL   = "https://oauth2.googleapis.com/revoke"

	stateFilename       = "auth_state.json"
	refreshMargin       = 30 * time.Second
	defaultBaseCooldown = 5 * time.Second
	maxCooldown         = 60 * time.Second
	httpTimeout         = 15 * time.Second
	maxHTTPBodyBytes    = 1024 * 1024
)

var (
	authAllowedHosts     = map[string]bool{"accounts.google.com": true}
	tokenAllowedHosts    = map[string]bool{"oauth2.googleapis.com": true, "accounts.google.com": true}
	userinfoAllowedHosts = map[string]bool{"www.googleapis.com": true, "openidconnect.googleapis.com": true}
	revokeAllowedHosts   = map[string]bool{"oauth2.googleapis.com": true, "accounts.google.com": true}
	loopbackHosts        = map[string]bool{"127.0.0.1": true, "localhost": true}
)

type Stage string

const (
	StageClientConfig    Stage = "oauth_client_config"
	StageClientAdmission Stage = "oauth_client_admission"
	StageAuthorization   Stage = "oauth_authorization"
	StageCodeExchange    Stage = "oauth_code_exchange"
	StageAccountProfile  Stage = "oauth_account_profile"
	StageRefresh         Stage = "oauth_refresh"
	StageLocalSession    Stage = "local_session"
)

// Error is a sanitized OAuth/credential error safe for logging and operator display.
type Error struct {
	Code       string
	Stage      Stage
	Message    string
	Status     int
	RetryAfter time.Duration
}

func withStage(err error, stage Stage) error {
	var e *Error
	if errors.As(err, &e) && e.Stage == "" {
		copy := *e
		copy.Stage = stage
		return &copy
	}
	return err
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Config configures the installed-app OAuth2 client constrained to Google HTTPS endpoints.
type Config struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	AuthURL      string
	TokenURL     string
	UserinfoURL  string
	RevokeURL    string
	RedirectHost string
	CallbackPath string
	DefaultPort  int
}

func (c Config) String() string {
	return fmt.Sprintf("auth.Config{Scopes:%d}", len(c.Scopes))
}

func (c Config) GoString() string {
	return c.String()
}

// Validate normalizes defaults and verifies strict Google HTTPS and loopback constraints.
func (c *Config) Validate() error {
	if c == nil {
		return &Error{Code: "invalid_config", Message: "nil OAuth config"}
	}
	tmp := *c
	if strings.TrimSpace(tmp.ClientID) == "" || hasControlOrSpace(tmp.ClientID) {
		return &Error{Code: "invalid_config", Message: "invalid OAuth client_id"}
	}
	tmp.ClientID = strings.TrimSpace(tmp.ClientID)

	if strings.TrimSpace(tmp.ClientSecret) == "" || strings.ContainsAny(tmp.ClientSecret, "\r\n\x00") {
		return &Error{Code: "invalid_config", Message: "invalid OAuth client_secret"}
	}

	seen := make(map[string]bool, len(tmp.Scopes))
	normalized := make([]string, 0, len(tmp.Scopes))
	for _, raw := range tmp.Scopes {
		s := strings.TrimSpace(raw)
		if s == "" || hasControlOrSpace(s) {
			return &Error{Code: "invalid_config", Message: "invalid OAuth scope format"}
		}
		if !seen[s] {
			seen[s] = true
			normalized = append(normalized, s)
		}
	}
	if len(normalized) == 0 {
		return &Error{Code: "invalid_config", Message: "at least one OAuth scope is required"}
	}
	tmp.Scopes = normalized

	if tmp.AuthURL == "" {
		tmp.AuthURL = GoogleAuthURL
	}
	if tmp.TokenURL == "" {
		tmp.TokenURL = GoogleTokenURL
	}
	if tmp.UserinfoURL == "" {
		tmp.UserinfoURL = GoogleUserinfoURL
	}
	if tmp.RevokeURL == "" {
		tmp.RevokeURL = GoogleRevokeURL
	}
	if tmp.RedirectHost == "" {
		tmp.RedirectHost = "127.0.0.1"
	}
	if tmp.CallbackPath == "" {
		tmp.CallbackPath = "/CALLBACK_AUTH"
	}

	var err error
	if tmp.AuthURL, err = validateGoogleHTTPSURL(tmp.AuthURL, authAllowedHosts, "auth_url"); err != nil {
		return err
	}
	if tmp.TokenURL, err = validateGoogleHTTPSURL(tmp.TokenURL, tokenAllowedHosts, "token_url"); err != nil {
		return err
	}
	if tmp.UserinfoURL, err = validateGoogleHTTPSURL(tmp.UserinfoURL, userinfoAllowedHosts, "userinfo_url"); err != nil {
		return err
	}
	if tmp.RevokeURL, err = validateGoogleHTTPSURL(tmp.RevokeURL, revokeAllowedHosts, "revoke_url"); err != nil {
		return err
	}

	host := strings.ToLower(strings.TrimSpace(tmp.RedirectHost))
	if !loopbackHosts[host] {
		return &Error{Code: "invalid_config", Message: "redirect_host must be a loopback address"}
	}
	tmp.RedirectHost = host

	if !strings.HasPrefix(tmp.CallbackPath, "/") || hasControlOrSpace(tmp.CallbackPath) || strings.ContainsAny(tmp.CallbackPath, "?#") {
		return &Error{Code: "invalid_config", Message: "invalid callback_path"}
	}
	if tmp.DefaultPort < 0 || tmp.DefaultPort > 65535 {
		return &Error{Code: "invalid_config", Message: "invalid default_port"}
	}
	*c = tmp
	return nil
}

func hasControlOrSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b <= 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

func validateGoogleHTTPSURL(raw string, allowedHosts map[string]bool, fieldName string) (string, error) {
	if strings.TrimSpace(raw) == "" || hasControlOrSpace(raw) {
		return "", &Error{Code: "invalid_config", Message: fmt.Sprintf("invalid %s", fieldName)}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", &Error{Code: "invalid_config", Message: fmt.Sprintf("malformed %s", fieldName)}
	}
	if strings.ToLower(u.Scheme) != "https" {
		return "", &Error{Code: "invalid_config", Message: fmt.Sprintf("invalid %s: HTTPS required", fieldName)}
	}
	if u.User != nil {
		return "", &Error{Code: "invalid_config", Message: fmt.Sprintf("invalid %s: embedded credentials forbidden", fieldName)}
	}
	host := strings.ToLower(u.Hostname())
	if !allowedHosts[host] {
		return "", &Error{Code: "invalid_config", Message: fmt.Sprintf("invalid %s: untrusted host", fieldName)}
	}
	if p := u.Port(); p != "" && p != "443" {
		return "", &Error{Code: "invalid_config", Message: fmt.Sprintf("invalid %s: non-standard HTTPS port forbidden", fieldName)}
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", &Error{Code: "invalid_config", Message: fmt.Sprintf("invalid %s: query or fragment forbidden", fieldName)}
	}
	if u.Path == "" || u.Path == "/" {
		return "", &Error{Code: "invalid_config", Message: fmt.Sprintf("invalid %s: endpoint path required", fieldName)}
	}
	clean := url.URL{Scheme: "https", Host: host, Path: u.Path}
	return clean.String(), nil
}

// Status describes the non-secret operator state of the active local Google session.
type Status struct {
	LoggedIn             bool     `json:"logged_in"`
	ReauthRequired       bool     `json:"reauth_required"`
	ClientConfigError    string   `json:"client_config_error,omitempty"`
	Email                *string  `json:"email"`
	HasAccessToken       bool     `json:"has_access_token"`
	AccessTokenExpiresIn *float64 `json:"access_token_expires_in"`
	CooldownRemaining    float64  `json:"cooldown_remaining"`
	UpdatedAt            *string  `json:"updated_at"`
}

type persistedAccount struct {
	Email   string  `json:"email"`
	Subject *string `json:"subject,omitempty"`
	Name    *string `json:"name,omitempty"`
}

type persistedState struct {
	Version        int               `json:"version"`
	ClientID       string            `json:"client_id"`
	Scopes         []string          `json:"scopes"`
	Account        *persistedAccount `json:"account"`
	RefreshToken   *string           `json:"refresh_token"`
	ReauthRequired bool              `json:"reauth_required"`
	UpdatedAt      *string           `json:"updated_at"`
}

type refreshCall struct {
	done  chan struct{}
	gen   uint64
	token string
	err   error
}

// Manager manages OAuth2 PKCE login, 0600 refresh-token persistence, and singleflight token refreshes.
type Manager struct {
	config       Config
	stateDir     string
	initErr      error
	unconfigured bool
	now          func() time.Time
	httpClient   *http.Client
	baseCooldown time.Duration

	mu                  sync.Mutex
	accessToken         string
	hasAccessToken      bool
	expiresAt           time.Time
	refreshToken        string
	account             *persistedAccount
	reauthRequired      bool
	updatedAt           *string
	cooldownUntil       time.Time
	consecutiveFailures int
	lastTransientStatus int
	refreshBlocked      *Error
	loadedFromDisk      bool
	diskIdentity        *fileIdentity
	gen                 uint64
	inflight            *refreshCall
}

// NewManager creates an OAuth lifecycle manager for config and stateDir.
func NewManager(config Config, stateDir string) *Manager {
	cfg := config
	initErr := cfg.Validate()
	if initErr == nil && strings.TrimSpace(stateDir) == "" {
		initErr = &Error{Code: "invalid_config", Message: "stateDir must not be empty"}
	}
	return &Manager{
		config:       cfg,
		stateDir:     stateDir,
		initErr:      initErr,
		now:          time.Now,
		httpClient:   newStrictHTTPClient(),
		baseCooldown: defaultBaseCooldown,
	}
}

// NewUnconfiguredManager allows liveness and local status without any token access.
func NewUnconfiguredManager() *Manager {
	return &Manager{initErr: clientNotConfigured(), unconfigured: true}
}

func newStrictHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return &Error{Code: "unexpected_redirect", Message: "unexpected redirect from OAuth endpoint"}
		},
	}
}

func sanitizeOAuthError(v string) string {
	switch v {
	case "restricted_client", "invalid_client", "unauthorized_client", "invalid_scope", "redirect_uri_mismatch",
		"access_denied", "invalid_grant", "invalid_request", "unsupported_grant_type", "unsupported_response_type",
		"server_error", "temporarily_unavailable", "admin_policy_enforced", "org_internal", "disallowed_useragent":
		return v
	default:
		return ""
	}
}

func clientRejected(code string) bool {
	switch code {
	case "restricted_client", "invalid_client", "unauthorized_client", "invalid_scope", "redirect_uri_mismatch":
		return true
	default:
		return false
	}
}

func sessionChangedError() *Error {
	return &Error{Code: "session_changed", Stage: StageRefresh, Message: "the Google session changed while refreshing; retry the request"}
}

func generatePKCE() (verifier string, challenge string, err error) {
	var buf [48]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", "", &Error{Code: "auth_error", Message: "failed generating PKCE verifier"}
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf[:])
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

func generateState() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", &Error{Code: "auth_error", Message: "failed generating OAuth state"}
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func parseExpiresIn(raw *float64) (time.Duration, error) {
	if raw == nil {
		return time.Hour, nil
	}
	val := *raw
	if math.IsNaN(val) || math.IsInf(val, 0) || val <= 0 {
		return 0, &Error{Code: "invalid_token_response", Message: "token response contained non-finite or non-positive expires_in"}
	}
	if val > 365*86400 {
		val = 365 * 86400
	}
	return time.Duration(val * float64(time.Second)), nil
}

func parseRetryAfter(h http.Header) (time.Duration, bool) {
	raw := strings.TrimSpace(h.Get("Retry-After"))
	if raw == "" {
		return 0, false
	}
	val, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(val) || math.IsInf(val, 0) || val <= 0 {
		return 0, false
	}
	if val > 120 {
		val = 120
	}
	return time.Duration(val * float64(time.Second)), true
}

func validateGrantedScopes(rawScope *string, required []string) error {
	if rawScope == nil {
		return nil
	}
	fields := strings.Fields(*rawScope)
	if len(fields) == 0 {
		return &Error{Code: "missing_scope", Message: "OAuth token response contained empty scope set"}
	}
	granted := make(map[string]bool, len(fields))
	for _, s := range fields {
		granted[s] = true
	}
	for _, req := range required {
		if !scopeSatisfied(req, granted) {
			return &Error{Code: "missing_scope", Message: "OAuth token response missing mandatory scopes (granted: " + describeGrantedScopes(fields) + ")"}
		}
	}
	return nil
}

// scopeSatisfied reports whether a requested scope is covered by the granted
// set. Google does not echo OAuthScope.Flexible back verbatim: the token
// endpoint expands it into the packaged first-party bundle, which includes
// aicode plus the account profile scopes. Treat that expansion as satisfying
// the Flexible request instead of failing the exchange.
func scopeSatisfied(required string, granted map[string]bool) bool {
	if granted[required] {
		return true
	}
	return required == fstScope && granted[aiCodeScope]
}

// describeGrantedScopes renders a bounded list of recognizable OAuth scope
// names for diagnostics. Scope identifiers are not credentials; anything that
// does not look like a Google scope marker is reported as unrecognized.
func describeGrantedScopes(fields []string) string {
	kept := make([]string, 0, len(fields))
	for _, f := range fields {
		if strings.HasPrefix(f, "https://www.googleapis.com/auth/") || f == "openid" || f == "email" || f == "profile" {
			if len(f) <= 80 {
				kept = append(kept, f)
			}
		} else {
			kept = append(kept, "unrecognized")
		}
	}
	if len(kept) == 0 {
		return "none"
	}
	if len(kept) > 12 {
		kept = append(kept[:12], "...")
	}
	return strings.Join(kept, " ")
}

func (m *Manager) clearInMemorySessionLocked() {
	m.gen++
	m.accessToken = ""
	m.hasAccessToken = false
	m.expiresAt = time.Time{}
	m.refreshToken = ""
	m.account = nil
	m.reauthRequired = false
	m.updatedAt = nil
	m.cooldownUntil = time.Time{}
	m.consecutiveFailures = 0
	m.lastTransientStatus = 0
	m.refreshBlocked = nil
	m.diskIdentity = nil
}

func (m *Manager) syncFromDiskLocked() error {
	raw, id, err := readPersistedRaw(m.stateDir)
	if err != nil {
		return err
	}
	if id == nil {
		if m.loadedFromDisk {
			m.clearInMemorySessionLocked()
		}
		m.loadedFromDisk = true
		m.diskIdentity = nil
		return nil
	}

	if m.loadedFromDisk && m.diskIdentity != nil && sameIdentity(*m.diskIdentity, *id) {
		return nil
	}

	if m.loadedFromDisk {
		m.accessToken = ""
		m.hasAccessToken = false
		m.expiresAt = time.Time{}
		m.cooldownUntil = time.Time{}
		m.consecutiveFailures = 0
		m.lastTransientStatus = 0
		m.refreshBlocked = nil
		m.gen++
	}

	var st persistedState
	if err := json.Unmarshal(raw, &st); err != nil || st.Version != 1 {
		return &Error{Code: "corrupt_state", Message: "corrupted or unsupported auth state file"}
	}
	if st.Scopes == nil {
		return &Error{Code: "corrupt_state", Message: "corrupted scopes in auth state"}
	}
	if st.RefreshToken != nil {
		rt := *st.RefreshToken
		if strings.TrimSpace(rt) == "" || hasControlOrSpace(rt) {
			return &Error{Code: "corrupt_state", Message: "corrupted refresh token entry in auth state"}
		}
	}
	if st.Account != nil && (strings.TrimSpace(st.Account.Email) == "" || !strings.Contains(st.Account.Email, "@")) {
		return &Error{Code: "corrupt_state", Message: "corrupted account metadata in auth state"}
	}

	m.loadedFromDisk = true
	m.diskIdentity = id

	scopesOK := true
	storedScopes := make(map[string]bool, len(st.Scopes))
	for _, s := range st.Scopes {
		storedScopes[s] = true
	}
	for _, req := range m.config.Scopes {
		if !storedScopes[req] {
			scopesOK = false
			break
		}
	}

	if st.ClientID != m.config.ClientID || !scopesOK {
		m.refreshToken = ""
		m.account = st.Account
		m.reauthRequired = true
		m.updatedAt = st.UpdatedAt
		return nil
	}

	if st.RefreshToken != nil && st.Account == nil {
		return &Error{Code: "corrupt_state", Message: "auth state refresh token missing verified account"}
	}

	if st.RefreshToken != nil {
		m.refreshToken = *st.RefreshToken
	} else {
		m.refreshToken = ""
	}
	m.account = st.Account
	m.reauthRequired = st.ReauthRequired || st.RefreshToken == nil
	m.updatedAt = st.UpdatedAt
	return nil
}

func (m *Manager) writeStateLocked(refreshToken *string, account *persistedAccount, reauthRequired bool, updatedAt string) error {
	payload := persistedState{
		Version:        1,
		ClientID:       m.config.ClientID,
		Scopes:         slices.Clone(m.config.Scopes),
		Account:        account,
		RefreshToken:   refreshToken,
		ReauthRequired: reauthRequired,
		UpdatedAt:      &updatedAt,
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return &Error{Code: "auth_error", Message: "failed encoding auth state"}
	}
	encoded = append(encoded, '\n')
	id, err := writePersistedRaw(m.stateDir, encoded)
	if err != nil {
		return err
	}
	m.diskIdentity = &id
	m.loadedFromDisk = true
	return nil
}

func (m *Manager) doHTTP(ctx context.Context, method, rawURL string, headers map[string]string, body io.Reader) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return 0, nil, nil, &Error{Code: "invalid_config", Message: "failed constructing OAuth HTTP request"}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		var authErr *Error
		if errors.As(err, &authErr) {
			return 0, nil, nil, authErr
		}
		return 0, nil, nil, &Error{Code: "network_error", Message: "OAuth HTTPS network request failed"}
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodyBytes+1))
	if err != nil {
		return 0, nil, nil, &Error{Code: "network_error", Message: "failed reading OAuth HTTPS response"}
	}
	if len(raw) > maxHTTPBodyBytes {
		return 0, nil, nil, &Error{Code: "response_too_large", Message: "OAuth endpoint response exceeded size limit"}
	}
	if resp.StatusCode < 100 || resp.StatusCode > 599 {
		return 0, nil, nil, &Error{Code: "network_error", Message: "malformed HTTP status from OAuth endpoint"}
	}
	return resp.StatusCode, resp.Header, raw, nil
}

type tokenResponsePayload struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    *float64 `json:"expires_in"`
	Scope        *string  `json:"scope"`
	IDToken      string   `json:"id_token"`
	Error        string   `json:"error"`
}

func (m *Manager) exchangeCode(ctx context.Context, code, redirectURI, verifier string) (accessToken string, refreshToken string, idToken string, expiry time.Duration, resultErr error) {
	defer func() { resultErr = withStage(resultErr, StageCodeExchange) }()
	if _, err := validateGoogleHTTPSURL(m.config.TokenURL, tokenAllowedHosts, "token_url"); err != nil {
		return "", "", "", 0, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {m.config.ClientID},
		"client_secret": {m.config.ClientSecret},
		"code_verifier": {verifier},
	}
	reqCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	status, _, raw, err := m.doHTTP(reqCtx, http.MethodPost, m.config.TokenURL, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "application/json",
	}, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", "", 0, err
	}

	if status != http.StatusOK {
		var errBody tokenResponsePayload
		_ = json.Unmarshal(raw, &errBody)
		codeLabel := sanitizeOAuthError(errBody.Error)
		if codeLabel == "" {
			codeLabel = "token_exchange_failed"
		}
		return "", "", "", 0, &Error{
			Code:    codeLabel,
			Message: fmt.Sprintf("OAuth token exchange failed (error=%s, status=%d)", codeLabel, status),
			Status:  status,
		}
	}

	var payload tokenResponsePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", "", "", 0, &Error{Code: "invalid_token_response", Message: "malformed OAuth token exchange response"}
	}
	// RFC 6749 §5.1 permits omitting scope when it equals the requested set.
	// A successful code exchange still does not prove that AiCode accepts the token.
	if err := validateGrantedScopes(payload.Scope, m.config.Scopes); err != nil {
		return "", "", "", 0, err
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return "", "", "", 0, &Error{Code: "invalid_token_response", Message: "OAuth token response missing access_token"}
	}
	if strings.TrimSpace(payload.RefreshToken) == "" {
		return "", "", "", 0, &Error{Code: "missing_refresh_token", Message: "OAuth token response missing offline refresh_token"}
	}
	expiresIn, err := parseExpiresIn(payload.ExpiresIn)
	if err != nil {
		return "", "", "", 0, err
	}
	return payload.AccessToken, payload.RefreshToken, payload.IDToken, expiresIn, nil
}

// accountFromIDToken reads the account identity from an ID token that was
// received directly from Google's token endpoint over TLS (the confidential
// channel defined by OIDC Core §3.1.3.7). It still checks issuer, audience and
// the verified-email claim before trusting the identity.
func (m *Manager) accountFromIDToken(raw string) (*persistedAccount, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, &Error{Code: "invalid_id_token", Message: "malformed ID token from Google token endpoint"}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, &Error{Code: "invalid_id_token", Message: "malformed ID token payload"}
	}
	var claims struct {
		Issuer        string          `json:"iss"`
		Audience      json.RawMessage `json:"aud"`
		Email         string          `json:"email"`
		EmailVerified *bool           `json:"email_verified"`
		Subject       string          `json:"sub"`
		Name          string          `json:"name"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, &Error{Code: "invalid_id_token", Message: "malformed ID token claims"}
	}
	if claims.Issuer != "accounts.google.com" && claims.Issuer != "https://accounts.google.com" {
		return nil, &Error{Code: "invalid_id_token", Message: "ID token issuer is not Google"}
	}
	var aud string
	if json.Unmarshal(claims.Audience, &aud) != nil {
		var auds []string
		if json.Unmarshal(claims.Audience, &auds) != nil || len(auds) == 0 {
			return nil, &Error{Code: "invalid_id_token", Message: "ID token audience is malformed"}
		}
		aud = auds[0]
	}
	if subtle.ConstantTimeCompare([]byte(aud), []byte(m.config.ClientID)) != 1 {
		return nil, &Error{Code: "invalid_id_token", Message: "ID token audience does not match the configured client"}
	}
	email := strings.TrimSpace(claims.Email)
	if email == "" || !strings.Contains(email, "@") || hasControlOrSpace(email) {
		return nil, &Error{Code: "unverified_account", Message: "ID token missing an account email"}
	}
	if claims.EmailVerified == nil || !*claims.EmailVerified {
		return nil, &Error{Code: "unverified_account", Message: "Google account email is not verified"}
	}
	var subjPtr, namePtr *string
	if s := strings.TrimSpace(claims.Subject); s != "" {
		subjPtr = &s
	}
	if n := strings.TrimSpace(claims.Name); n != "" {
		namePtr = &n
	}
	return &persistedAccount{Email: email, Subject: subjPtr, Name: namePtr}, nil
}

type userinfoPayload struct {
	ID            string `json:"id"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	VerifiedEmail *bool  `json:"verified_email"`
	EmailVerified *bool  `json:"email_verified"`
	Name          string `json:"name"`
}

func (m *Manager) fetchVerifiedUserinfo(ctx context.Context, accessToken string) (*persistedAccount, error) {
	if _, err := validateGoogleHTTPSURL(m.config.UserinfoURL, userinfoAllowedHosts, "userinfo_url"); err != nil {
		return nil, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	status, _, raw, err := m.doHTTP(reqCtx, http.MethodGet, m.config.UserinfoURL, map[string]string{
		"Authorization": "Bearer " + accessToken,
		"Accept":        "application/json",
	}, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &Error{
			Code:    "userinfo_failed",
			Message: fmt.Sprintf("failed to verify Google account profile (status=%d)", status),
			Status:  status,
		}
	}

	var ui userinfoPayload
	if err := json.Unmarshal(raw, &ui); err != nil {
		return nil, &Error{Code: "userinfo_failed", Message: "malformed Google userinfo response"}
	}
	email := strings.TrimSpace(ui.Email)
	if email == "" || !strings.Contains(email, "@") {
		return nil, &Error{Code: "unverified_account", Message: "Google userinfo missing verified email"}
	}
	verified := ui.VerifiedEmail
	if verified == nil {
		verified = ui.EmailVerified
	}
	if verified == nil || !*verified {
		return nil, &Error{Code: "unverified_account", Message: "Google account email is not verified"}
	}

	var subjPtr, namePtr *string
	if s := strings.TrimSpace(ui.ID); s != "" {
		subjPtr = &s
	} else if s := strings.TrimSpace(ui.Sub); s != "" {
		subjPtr = &s
	}
	if n := strings.TrimSpace(ui.Name); n != "" {
		namePtr = &n
	}
	return &persistedAccount{Email: email, Subject: subjPtr, Name: namePtr}, nil
}

const loginAttemptTTL = 15 * time.Minute

// LoginAttempt holds the server-side state of one interactive authorization.
// It is safe to keep in memory only; State and Verifier are never exposed.
type LoginAttempt struct {
	State       string
	Verifier    string
	RedirectURI string
	CreatedAt   time.Time
}

// BeginLogin builds the Google authorization URL for redirectURI and returns
// the attempt that CompleteLogin must consume. redirectURI is strictly a
// loopback callback URI with the configured path, never caller-selected.
func (m *Manager) BeginLogin(redirectURI string) (string, *LoginAttempt, error) {
	if m.initErr != nil {
		return "", nil, withStage(m.initErr, StageClientConfig)
	}
	if _, err := validateGoogleHTTPSURL(m.config.AuthURL, authAllowedHosts, "auth_url"); err != nil {
		return "", nil, err
	}
	if _, err := validateGoogleHTTPSURL(m.config.TokenURL, tokenAllowedHosts, "token_url"); err != nil {
		return "", nil, err
	}
	if _, err := validateGoogleHTTPSURL(m.config.UserinfoURL, userinfoAllowedHosts, "userinfo_url"); err != nil {
		return "", nil, err
	}
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!loopbackHosts[strings.ToLower(u.Hostname())] || u.Port() == "" || u.Path != m.config.CallbackPath {
		return "", nil, &Error{Code: "invalid_redirect_uri", Message: "login redirect must be a loopback HTTP callback URI"}
	}
	state, err := generateState()
	if err != nil {
		return "", nil, err
	}
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", nil, err
	}
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {m.config.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(m.config.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"access_type":           {"offline"},
	}
	return m.config.AuthURL + "?" + params.Encode(), &LoginAttempt{
		State: state, Verifier: verifier, RedirectURI: redirectURI, CreatedAt: m.now(),
	}, nil
}

// ParseCallback extracts the authorization code from the URL Google redirected
// to (or from a bare code pasted by the operator). A full callback URL must
// carry the matching state.
func (a *LoginAttempt) ParseCallback(raw string) (string, error) {
	if a == nil {
		return "", &Error{Code: "no_pending_login", Message: "start a login before submitting a callback"}
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", &Error{Code: "invalid_callback", Message: "callback URL or authorization code is required"}
	}
	code := raw
	if strings.Contains(raw, "?") || strings.Contains(raw, "://") {
		expected, err := url.Parse(a.RedirectURI)
		if err != nil {
			return "", &Error{Code: "invalid_redirect_uri", Message: "pending login has an invalid redirect URI"}
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || u.User != nil || u.Host != expected.Host || u.Path != expected.Path || u.Fragment != "" {
			return "", &Error{Code: "invalid_callback", Message: "callback URL does not match the pending loopback redirect"}
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return "", &Error{Code: "invalid_callback", Message: "callback query is malformed"}
		}
		states := q["state"]
		if len(states) != 1 || subtle.ConstantTimeCompare([]byte(states[0]), []byte(a.State)) != 1 {
			return "", &Error{Code: "state_mismatch", Message: "callback state does not match the pending login"}
		}
		if errVals := q["error"]; len(errVals) > 0 {
			codeLabel := sanitizeOAuthError(errVals[0])
			if codeLabel == "" {
				codeLabel = "authorization_failed"
			}
			return "", &Error{Code: codeLabel, Message: "Google returned an authorization error"}
		}
		codes := q["code"]
		if len(codes) != 1 {
			return "", &Error{Code: "missing_code", Message: "callback must contain exactly one authorization code"}
		}
		code = codes[0]
	}
	if code == "" || len(code) > 4096 || hasControlOrSpace(code) {
		return "", &Error{Code: "missing_code", Message: "callback is missing a valid authorization code"}
	}
	return code, nil
}

// CompleteLogin exchanges an authorization code from a pending attempt and
// persists the resulting session.
func (m *Manager) CompleteLogin(ctx context.Context, attempt *LoginAttempt, code string) (result Status, resultErr error) {
	defer func() { resultErr = withStage(resultErr, StageAuthorization) }()
	if m.initErr != nil {
		return Status{}, withStage(m.initErr, StageClientConfig)
	}
	if attempt == nil || attempt.State == "" || attempt.Verifier == "" || attempt.RedirectURI == "" {
		return Status{}, &Error{Code: "no_pending_login", Message: "start a login before completing authorization"}
	}
	if m.now().Sub(attempt.CreatedAt) > loginAttemptTTL {
		return Status{}, &Error{Code: "attempt_expired", Message: "authorization attempt expired; start login again"}
	}
	if code == "" || len(code) > 4096 || hasControlOrSpace(code) {
		return Status{}, &Error{Code: "missing_code", Message: "authorization code is missing or invalid"}
	}

	accessTok, refreshTok, idToken, expiresIn, err := m.exchangeCode(ctx, code, attempt.RedirectURI, attempt.Verifier)
	if err != nil {
		return Status{}, err
	}
	var account *persistedAccount
	if idToken != "" {
		account, err = m.accountFromIDToken(idToken)
	} else {
		// The IDE receives an ID token from the token endpoint; userinfo is only
		// a fallback for token responses that omitted it.
		account, err = m.fetchVerifiedUserinfo(ctx, accessTok)
	}
	if err != nil {
		return Status{}, withStage(err, StageAccountProfile)
	}
	updatedAt := m.now().UTC().Format(time.RFC3339Nano)

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.writeStateLocked(&refreshTok, account, false, updatedAt); err != nil {
		return Status{}, withStage(err, StageLocalSession)
	}
	m.gen++
	m.accessToken = accessTok
	m.hasAccessToken = true
	m.expiresAt = m.now().Add(expiresIn)
	m.refreshToken = refreshTok
	m.account = account
	m.reauthRequired = false
	m.updatedAt = &updatedAt
	m.cooldownUntil = time.Time{}
	m.consecutiveFailures = 0
	m.lastTransientStatus = 0
	m.refreshBlocked = nil

	return m.buildStatusLocked(m.now()), nil
}

// Login runs interactive headless loopback OAuth2 + PKCE authorization on 127.0.0.1:<port>.
func (m *Manager) Login(ctx context.Context, port int, display func(string) error) (result Status, resultErr error) {
	defer func() { resultErr = withStage(resultErr, StageAuthorization) }()
	if m.initErr != nil {
		return Status{}, withStage(m.initErr, StageClientConfig)
	}
	if port < 0 || port > 65535 {
		return Status{}, &Error{Code: "invalid_argument", Message: "port must be between 0 and 65535"}
	}
	if display == nil {
		return Status{}, &Error{Code: "invalid_argument", Message: "display callback must not be nil"}
	}
	if err := ctx.Err(); err != nil {
		return Status{}, &Error{Code: "cancelled", Message: "OAuth login cancelled before start"}
	}
	// Bind strictly to IPv4 loopback 127.0.0.1 for SSH port forwarding / container namespace access.
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return Status{}, &Error{Code: "loopback_bind_failed", Message: "failed to bind loopback OAuth callback port"}
	}
	boundPort := ln.Addr().(*net.TCPAddr).Port
	allowedHosts := map[string]bool{
		fmt.Sprintf("127.0.0.1:%d", boundPort):                 true,
		fmt.Sprintf("localhost:%d", boundPort):                 true,
		fmt.Sprintf("%s:%d", m.config.RedirectHost, boundPort): true,
	}
	redirectURI := fmt.Sprintf("http://%s:%d%s", m.config.RedirectHost, boundPort, m.config.CallbackPath)
	authURL, attempt, err := m.BeginLogin(redirectURI)
	if err != nil {
		_ = ln.Close()
		return Status{}, err
	}

	var cbMu sync.Mutex
	var consumed bool
	var sawBadState bool
	var authCode string
	var cbErrCode string
	doneCh := make(chan struct{})

	writeHTML := func(w http.ResponseWriter, statusCode int, bodyText string) {
		body := "<!doctype html><html><head><meta charset='utf-8'><title>ASGemini2API OAuth</title></head><body><p>" + bodyText + "</p></body></html>"
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(statusCode)
		_, _ = io.WriteString(w, body)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeHTML(w, http.StatusMethodNotAllowed, "Method not allowed.")
			return
		}
		hostHdr := strings.ToLower(strings.TrimSpace(r.Host))
		if !allowedHosts[hostHdr] {
			writeHTML(w, http.StatusBadRequest, "Invalid loopback host header.")
			return
		}
		if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && strings.ToLower(strings.TrimSpace(mode)) != "navigate" {
			writeHTML(w, http.StatusForbidden, "Forbidden non-navigation callback request.")
			return
		}
		if r.URL.Path != m.config.CallbackPath {
			writeHTML(w, http.StatusNotFound, "Not found.")
			return
		}

		q := r.URL.Query()
		stateVals := q["state"]
		gotState := ""
		if len(stateVals) == 1 {
			gotState = stateVals[0]
		}
		if gotState == "" || subtle.ConstantTimeCompare([]byte(gotState), []byte(attempt.State)) != 1 {
			cbMu.Lock()
			sawBadState = true
			cbMu.Unlock()
			writeHTML(w, http.StatusBadRequest, "Invalid OAuth state parameter.")
			return
		}

		cbMu.Lock()
		if consumed {
			cbMu.Unlock()
			writeHTML(w, http.StatusConflict, "OAuth callback already processed.")
			return
		}
		consumed = true

		if errVals := q["error"]; len(errVals) > 0 {
			cbErrCode = sanitizeOAuthError(errVals[0])
			if cbErrCode == "" {
				cbErrCode = "authorization_failed"
			}
			close(doneCh)
			cbMu.Unlock()
			writeHTML(w, http.StatusBadRequest, "Authorization was cancelled or denied. You may close this tab.")
			return
		}

		codeVals := q["code"]
		codeVal := ""
		if len(codeVals) == 1 {
			codeVal = codeVals[0]
		}
		if codeVal == "" || len(codeVal) > 4096 || hasControlOrSpace(codeVal) {
			cbErrCode = "missing_code"
			close(doneCh)
			cbMu.Unlock()
			writeHTML(w, http.StatusBadRequest, "Missing or invalid authorization code.")
			return
		}

		authCode = codeVal
		close(doneCh)
		cbMu.Unlock()
		writeHTML(w, http.StatusOK, "Authorization code received. Return to the CLI to see whether login completed.")
	})

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(ln)
	}()

	shutdownServer := func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		_ = srv.Close()
		<-serveDone
	}

	if err := display(authURL); err != nil {
		shutdownServer()
		return Status{}, &Error{Code: "display_failed", Message: "failed presenting OAuth authorization URL"}
	}

	select {
	case <-doneCh:
		shutdownServer()
	case <-ctx.Done():
		shutdownServer()
		cbMu.Lock()
		badState := sawBadState
		cbMu.Unlock()
		if badState {
			return Status{}, &Error{Code: "state_mismatch", Message: "OAuth callback state verification failed"}
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return Status{}, &Error{Code: "cancelled", Message: "OAuth login cancelled"}
		}
		return Status{}, &Error{Code: "timeout", Message: "OAuth login timed out without a browser callback; check the Google page or the loopback connection"}
	}

	cbMu.Lock()
	errCode := cbErrCode
	code := authCode
	cbMu.Unlock()

	if errCode != "" {
		if clientRejected(errCode) {
			return Status{}, &Error{Code: errCode, Stage: StageClientAdmission, Message: "Google rejected the OAuth client configuration or requested scopes before issuing a code"}
		}
		return Status{}, &Error{Code: errCode, Message: "OAuth authorization failed before receiving a valid code"}
	}
	if code == "" {
		return Status{}, &Error{Code: "missing_code", Message: "OAuth callback missing authorization code"}
	}

	return m.CompleteLogin(ctx, attempt, code)
}

func (m *Manager) needsRefreshLocked(now time.Time, rejected string) bool {
	if !m.hasAccessToken || m.accessToken == "" {
		return true
	}
	if rejected != "" && rejected == m.accessToken {
		return true
	}
	return m.expiresAt.Sub(now) <= refreshMargin
}

// AccessToken returns a valid in-memory access token, performing singleflight refresh when needed.
func (m *Manager) AccessToken(ctx context.Context, rejected string) (string, error) {
	return m.acquireAccessToken(ctx, rejected, false)
}

func (m *Manager) acquireAccessToken(ctx context.Context, rejected string, retried bool) (string, error) {
	if m.initErr != nil {
		return "", m.initErr
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	m.mu.Lock()
	if err := m.syncFromDiskLocked(); err != nil {
		m.mu.Unlock()
		return "", withStage(err, StageLocalSession)
	}

	if blocked := m.refreshBlocked; blocked != nil {
		err := *blocked
		m.mu.Unlock()
		return "", &err
	}

	now := m.now()
	if !m.reauthRequired && m.refreshToken != "" && !m.needsRefreshLocked(now, rejected) {
		tok := m.accessToken
		m.mu.Unlock()
		return tok, nil
	}

	if m.inflight != nil {
		call := m.inflight
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-call.done:
			return call.token, call.err
		}
	}

	if m.reauthRequired || m.refreshToken == "" {
		m.mu.Unlock()
		return "", &Error{Code: "reauth_required", Stage: StageLocalSession, Message: "re-authentication required; run login with your registered client"}
	}

	if now.Before(m.cooldownUntil) {
		rem := m.cooldownUntil.Sub(now)
		status := m.lastTransientStatus
		m.mu.Unlock()
		return "", &Error{
			Code:       "transient_cooldown",
			Stage:      StageRefresh,
			Message:    "OAuth refresh in transient cooldown; retry later",
			Status:     status,
			RetryAfter: rem,
		}
	}

	call := &refreshCall{done: make(chan struct{}), gen: m.gen}
	m.inflight = call
	refreshTok := m.refreshToken
	account := m.account
	m.mu.Unlock()

	go m.runRefreshCall(call, refreshTok, account)

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-call.done:
		if call.err != nil && !retried {
			var authErr *Error
			if errors.As(call.err, &authErr) && authErr.Code == "session_changed" {
				return m.acquireAccessToken(ctx, rejected, true)
			}
		}
		return call.token, call.err
	}
}

func (m *Manager) runRefreshCall(call *refreshCall, refreshTok string, account *persistedAccount) {
	defer close(call.done)

	tok, err := m.executeRefreshHTTP(refreshTok, account, call.gen)

	m.mu.Lock()
	if m.inflight == call {
		m.inflight = nil
	}
	m.mu.Unlock()

	call.token = tok
	call.err = err
}

func (m *Manager) executeRefreshHTTP(refreshTok string, account *persistedAccount, gen uint64) (token string, resultErr error) {
	defer func() { resultErr = withStage(resultErr, StageRefresh) }()
	if _, err := validateGoogleHTTPSURL(m.config.TokenURL, tokenAllowedHosts, "token_url"); err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshTok},
		"client_id":     {m.config.ClientID},
		"client_secret": {m.config.ClientSecret},
	}

	reqCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	status, headers, raw, err := m.doHTTP(reqCtx, http.MethodPost, m.config.TokenURL, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "application/json",
	}, strings.NewReader(form.Encode()))
	if err != nil {
		delay := m.recordTransientFailure(gen, 0, nil)
		return "", &Error{Code: "transient_error", Message: "transient OAuth refresh network failure", RetryAfter: delay}
	}

	if status == http.StatusOK {
		var payload tokenResponsePayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			delay := m.recordTransientFailure(gen, status, headers)
			return "", &Error{Code: "transient_error", Message: "transient malformed OAuth refresh response", Status: status, RetryAfter: delay}
		}
		if err := validateGrantedScopes(payload.Scope, m.config.Scopes); err != nil {
			if persistErr := m.invalidateSessionOnReauth(gen, account); persistErr != nil {
				return "", withStage(persistErr, StageLocalSession)
			}
			return "", err
		}
		if strings.TrimSpace(payload.AccessToken) == "" {
			delay := m.recordTransientFailure(gen, status, headers)
			return "", &Error{Code: "transient_error", Message: "OAuth refresh response missing access_token", Status: status, RetryAfter: delay}
		}
		expiresIn, err := parseExpiresIn(payload.ExpiresIn)
		if err != nil {
			return "", &Error{Code: "invalid_token_response", Message: err.Error(), Status: status, RetryAfter: m.recordTransientFailure(gen, status, headers)}
		}

		effectiveRefresh := refreshTok
		if rotated := strings.TrimSpace(payload.RefreshToken); rotated != "" {
			effectiveRefresh = rotated
		}
		finishNow := m.now()
		updatedAt := finishNow.UTC().Format(time.RFC3339Nano)

		m.mu.Lock()
		defer m.mu.Unlock()
		if m.gen != gen {
			return "", sessionChangedError()
		}
		if effectiveRefresh != refreshTok {
			if err := m.writeStateLocked(&effectiveRefresh, account, false, updatedAt); err != nil {
				return "", err
			}
			m.updatedAt = &updatedAt
		}
		m.refreshToken = effectiveRefresh
		m.accessToken = payload.AccessToken
		m.hasAccessToken = true
		m.expiresAt = finishNow.Add(expiresIn)
		m.reauthRequired = false
		m.cooldownUntil = time.Time{}
		m.consecutiveFailures = 0
		m.lastTransientStatus = 0
		return payload.AccessToken, nil
	}

	var errBody tokenResponsePayload
	_ = json.Unmarshal(raw, &errBody)
	errCode := sanitizeOAuthError(errBody.Error)

	if errCode == "invalid_grant" && (status == http.StatusBadRequest || status == http.StatusUnauthorized) {
		if err := m.invalidateSessionOnReauth(gen, account); err != nil {
			return "", withStage(err, StageLocalSession)
		}
		return "", &Error{Code: errCode, Stage: StageRefresh, Message: "Google rejected the refresh grant; re-authorization is required", Status: status}
	}
	if clientRejected(errCode) && status >= 400 && status < 500 && status != http.StatusTooManyRequests {
		failure := Error{Code: errCode, Stage: StageRefresh, Message: "Google rejected the OAuth client during refresh; check the registration and restart", Status: status}
		m.mu.Lock()
		if m.gen != gen {
			m.mu.Unlock()
			return "", sessionChangedError()
		}
		blocked := failure
		m.refreshBlocked = &blocked
		m.mu.Unlock()
		return "", &failure
	}

	delay := m.recordTransientFailure(gen, status, headers)
	return "", &Error{
		Code:       "transient_error",
		Message:    fmt.Sprintf("transient OAuth refresh failure (status=%d)", status),
		Status:     status,
		RetryAfter: delay,
	}
}

func (m *Manager) invalidateSessionOnReauth(gen uint64, account *persistedAccount) error {
	updatedAt := m.now().UTC().Format(time.RFC3339Nano)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gen != gen {
		return sessionChangedError()
	}
	m.accessToken = ""
	m.hasAccessToken = false
	m.expiresAt = time.Time{}
	m.refreshToken = ""
	m.reauthRequired = true
	m.cooldownUntil = time.Time{}
	m.consecutiveFailures = 0
	m.lastTransientStatus = 0
	m.updatedAt = &updatedAt
	return m.writeStateLocked(nil, account, true, updatedAt)
}

func (m *Manager) recordTransientFailure(gen uint64, status int, headers http.Header) time.Duration {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gen != gen {
		return 0
	}
	delay, ok := parseRetryAfter(headers)
	if !ok {
		shift := min(m.consecutiveFailures, 10)
		delay = m.baseCooldown * time.Duration(1<<shift)
		if delay > maxCooldown {
			delay = maxCooldown
		}
	}
	m.consecutiveFailures++
	m.cooldownUntil = now.Add(delay)
	m.lastTransientStatus = status
	return delay
}

func (m *Manager) buildStatusLocked(now time.Time) Status {
	var expiresIn *float64
	if m.hasAccessToken {
		rem := m.expiresAt.Sub(now).Seconds()
		if math.IsNaN(rem) || math.IsInf(rem, 0) || rem < 0 {
			rem = 0
		}
		expiresIn = &rem
	}
	cooldownRem := 0.0
	if !m.cooldownUntil.IsZero() && now.Before(m.cooldownUntil) {
		rem := m.cooldownUntil.Sub(now).Seconds()
		if !math.IsNaN(rem) && !math.IsInf(rem, 0) && rem > 0 {
			cooldownRem = rem
		}
	}
	var emailPtr *string
	if m.account != nil && m.account.Email != "" {
		emailCopy := m.account.Email
		emailPtr = &emailCopy
	}
	var updatedPtr *string
	if m.updatedAt != nil {
		uCopy := *m.updatedAt
		updatedPtr = &uCopy
	}
	loggedIn := m.refreshToken != "" && !m.reauthRequired && m.account != nil
	var clientConfigError string
	if m.refreshBlocked != nil {
		clientConfigError = m.refreshBlocked.Code
	}
	return Status{
		LoggedIn:             loggedIn,
		ClientConfigError:    clientConfigError,
		ReauthRequired:       m.reauthRequired,
		Email:                emailPtr,
		HasAccessToken:       m.hasAccessToken,
		AccessTokenExpiresIn: expiresIn,
		CooldownRemaining:    cooldownRem,
		UpdatedAt:            updatedPtr,
	}
}

// Status returns safe non-secret operator status of the local credential state.
func (m *Manager) Status() (Status, error) {
	if m.unconfigured {
		return Status{ClientConfigError: "oauth_client_not_configured"}, nil
	}
	if m.initErr != nil {
		return Status{}, m.initErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.syncFromDiskLocked(); err != nil {
		return Status{}, withStage(err, StageLocalSession)
	}
	return m.buildStatusLocked(m.now()), nil
}

// ClearLocalSession removes local credentials without loading a client or contacting Google.
func ClearLocalSession(stateDir string) (bool, error) {
	removed, err := unlinkPersistedState(stateDir)
	return removed, withStage(err, StageLocalSession)
}

// Logout clears local in-memory and persisted credentials without remote revocation.
func (m *Manager) Logout() (bool, error) {
	if m.initErr != nil {
		return false, m.initErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	hadSession := m.hasAccessToken || m.refreshToken != ""
	if err := m.syncFromDiskLocked(); err != nil {
		// Allow local logout to clear corrupted/non-symlink files, but refuse symlinks.
		var authErr *Error
		if errors.As(err, &authErr) && authErr.Code == "insecure_storage" && strings.Contains(authErr.Message, "symlink") {
			return false, err
		}
	}
	if m.refreshToken != "" || m.account != nil {
		hadSession = true
	}

	unlinked, err := unlinkPersistedState(m.stateDir)
	if err != nil {
		return false, err
	}
	if unlinked {
		hadSession = true
	}
	m.clearInMemorySessionLocked()
	m.loadedFromDisk = true
	return hadSession, nil
}
