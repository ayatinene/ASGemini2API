package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonHTTPResponse(status int, hdrs map[string]string, body string) *http.Response {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func makeFakeConfig() Config {
	return Config{
		ClientID:     "fake-client-id.apps.googleusercontent.com",
		ClientSecret: "fake-client-secret-value",
		Scopes:       []string{fstScope},
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestManager(t *testing.T, cfg Config, dir string, clock *fakeClock, rt roundTripFunc) *Manager {
	t.Helper()
	m := NewManager(cfg, dir)
	if clock != nil {
		m.now = clock.Now
	}
	if rt != nil {
		m.httpClient = &http.Client{
			Timeout:       httpTimeout,
			Transport:     rt,
			CheckRedirect: m.httpClient.CheckRedirect,
		}
	}
	return m
}

func seedDiskState(t *testing.T, dir string, cfg Config, refreshToken string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, stateFilename)
	updated := "2026-11-20T00:00:00Z"
	payload := map[string]any{
		"version":         1,
		"client_id":       cfg.ClientID,
		"scopes":          cfg.Scopes,
		"account":         map[string]any{"email": "alice@example.com", "subject": "sub-1", "name": "Alice"},
		"refresh_token":   refreshToken,
		"reauth_required": false,
		"updated_at":      updated,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertAuthCode(t *testing.T, err error, code string) *Error {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", code)
	}
	var ae *Error
	if !errors.As(err, &ae) {
		t.Fatalf("expected *auth.Error, got %T: %v", err, err)
	}
	if ae.Code != code {
		t.Fatalf("expected error code %q, got %q (msg=%q)", code, ae.Code, ae.Message)
	}
	return ae
}

func TestConfigValidationAndRedaction(t *testing.T) {
	cfg := makeFakeConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(cfg.String(), "fake-client-secret-value") || strings.Contains(cfg.GoString(), "fake-client-secret-value") {
		t.Fatalf("Config String/GoString leaked client secret")
	}

	badConfigs := []func(*Config){
		func(c *Config) { c.AuthURL = "http://accounts.google.com/o/oauth2/auth" },
		func(c *Config) { c.TokenURL = "http://oauth2.googleapis.com/token" },
		func(c *Config) { c.TokenURL = "https://evil.example.com/token" },
		func(c *Config) { c.TokenURL = "https://oauth2.googleapis.com.evil.com/token" },
		func(c *Config) { c.TokenURL = "https://127.0.0.1/token" },
		func(c *Config) { c.TokenURL = "https://user@oauth2.googleapis.com/token" },
		func(c *Config) { c.TokenURL = "https://oauth2.googleapis.com:8443/token" },
		func(c *Config) { c.TokenURL = "https://oauth2.googleapis.com/token?x=1" },
		func(c *Config) { c.UserinfoURL = "https://evil.example.com/userinfo" },
		func(c *Config) { c.RevokeURL = "http://oauth2.googleapis.com/revoke" },
		func(c *Config) { c.RedirectHost = "0.0.0.0" },
		func(c *Config) { c.RedirectHost = "::" },
		func(c *Config) { c.CallbackPath = "no-slash" },
		func(c *Config) { c.ClientID = "  " },
		func(c *Config) { c.ClientSecret = "" },
		func(c *Config) { c.Scopes = nil },
		func(c *Config) { c.DefaultPort = 70000 },
	}
	for i, mutate := range badConfigs {
		bad := makeFakeConfig()
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatalf("case %d: expected validation failure", i)
		}
		m := NewManager(bad, t.TempDir())
		_, err := m.Status()
		assertAuthCode(t, err, "invalid_config")
	}
}

func makeFakeIDToken(t *testing.T, cfg Config, claims map[string]any) string {
	t.Helper()
	base := map[string]any{
		"iss":            "https://accounts.google.com",
		"aud":            cfg.ClientID,
		"email":          "alice@example.com",
		"email_verified": true,
		"sub":            "sub-1",
		"name":           "Alice",
	}
	for k, v := range claims {
		base[k] = v
	}
	payload, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	return "hdr." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestPKCELoginIDTokenStorageAndStatusJSON(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	clock := newFakeClock()
	var calls int
	var capturedVerifier string

	cfg := makeFakeConfig()
	rt := func(req *http.Request) (*http.Response, error) {
		calls++
		switch req.URL.String() {
		case GoogleTokenURL:
			b, _ := io.ReadAll(req.Body)
			vals, _ := url.ParseQuery(string(b))
			capturedVerifier = vals.Get("code_verifier")
			return jsonHTTPResponse(200, nil, `{
				"access_token":"fake-access-1",
				"refresh_token":"fake-refresh-1",
				"expires_in":3600,
				"scope":"`+fstScope+`",
				"id_token":"`+makeFakeIDToken(t, cfg, nil)+`"
			}`), nil
		case GoogleUserinfoURL:
			return jsonHTTPResponse(200, nil, `{
				"id":"sub-1",
				"email":"alice@example.com",
				"verified_email":true,
				"name":"Alice"
			}`), nil
		default:
			t.Fatalf("unexpected URL: %s", req.URL.String())
			return nil, nil
		}
	}

	mgr := newTestManager(t, cfg, stateDir, clock, rt)
	var shownURL string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st, err := mgr.Login(ctx, 0, func(authURL string) error {
		shownURL = authURL
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("access_type") != "offline" {
			t.Fatalf("unexpected auth params: %v", q)
		}
		if strings.Contains(authURL, "fake-client-secret-value") {
			t.Fatalf("auth URL leaked client secret")
		}
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")

		go func() {
			client := &http.Client{Timeout: 2 * time.Second}

			// 1. POST rejected with 405.
			resp, _ := client.Post(redirectURI+"?code=x&state="+state, "text/plain", nil)
			if resp != nil {
				_ = resp.Body.Close()
				if resp.StatusCode != 405 {
					t.Errorf("expected 405 on POST, got %d", resp.StatusCode)
				}
			}

			// 2. Non-navigation Sec-Fetch-Mode rejected with 403.
			rCors, _ := http.NewRequest(http.MethodGet, redirectURI+"?code=x&state="+state, nil)
			rCors.Header.Set("Sec-Fetch-Mode", "cors")
			resp, _ = client.Do(rCors)
			if resp != nil {
				_ = resp.Body.Close()
				if resp.StatusCode != 403 {
					t.Errorf("expected 403 on cors fetch, got %d", resp.StatusCode)
				}
			}

			// 3. DNS rebinding Host rejected with 400.
			rHost, _ := http.NewRequest(http.MethodGet, redirectURI+"?code=x&state="+state, nil)
			rHost.Host = "evil.example.com:80"
			resp, _ = client.Do(rHost)
			if resp != nil {
				_ = resp.Body.Close()
				if resp.StatusCode != 400 {
					t.Errorf("expected 400 on bad host, got %d", resp.StatusCode)
				}
			}

			// 4. Bad state rejected with 400 without breaking flow.
			resp, _ = client.Get(redirectURI + "?code=evil&state=wrong-state")
			if resp != nil {
				_ = resp.Body.Close()
				if resp.StatusCode != 400 {
					t.Errorf("expected 400 on bad state, got %d", resp.StatusCode)
				}
			}

			// 5. Valid callback.
			rGood, _ := http.NewRequest(http.MethodGet, redirectURI+"?code=good-code&state="+state, nil)
			rGood.Header.Set("Sec-Fetch-Mode", "navigate")
			resp, err := client.Do(rGood)
			if err != nil {
				t.Errorf("good callback failed: %v", err)
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("unexpected good callback response: %d", resp.StatusCode)
			}
		}()
		return nil
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if !st.LoggedIn || st.Email == nil || *st.Email != "alice@example.com" || !st.HasAccessToken {
		t.Fatalf("unexpected login status: %+v", st)
	}

	// Verify PKCE S256 match.
	u, _ := url.Parse(shownURL)
	sum := sha256.Sum256([]byte(capturedVerifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if u.Query().Get("code_challenge") != expectedChallenge {
		t.Fatalf("PKCE challenge mismatch")
	}

	// Verify exact Status JSON field names only.
	rawJSON, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(rawJSON, &keys); err != nil {
		t.Fatal(err)
	}
	expectedKeys := []string{
		"logged_in", "reauth_required", "email", "has_access_token",
		"access_token_expires_in", "cooldown_remaining", "updated_at",
	}
	if len(keys) != len(expectedKeys) {
		t.Fatalf("unexpected Status JSON keys: %v", keys)
	}
	for _, k := range expectedKeys {
		if _, ok := keys[k]; !ok {
			t.Fatalf("missing Status JSON key %q", k)
		}
	}

	// Verify 0700 dir, 0600 file, no access_token or client_secret on disk.
	dinfo, err := os.Stat(stateDir)
	if err != nil || dinfo.Mode().Perm() != 0o700 {
		t.Fatalf("unexpected stateDir mode: %v %v", dinfo.Mode().Perm(), err)
	}
	stateFile := filepath.Join(stateDir, stateFilename)
	finfo, err := os.Stat(stateFile)
	if err != nil || finfo.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected stateFile mode: %v %v", finfo.Mode().Perm(), err)
	}
	diskBytes, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	diskStr := string(diskBytes)
	if strings.Contains(diskStr, "fake-access-1") || strings.Contains(diskStr, "fake-client-secret-value") {
		t.Fatalf("sensitive data persisted on disk: %s", diskStr)
	}
}

func TestLoginMandatoryScopeEnforcementAndFixedPort(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	var userinfoCalled atomic.Bool
	rt := func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == GoogleUserinfoURL {
			userinfoCalled.Store(true)
			return jsonHTTPResponse(200, nil, `{"email":"a@example.com","verified_email":true}`), nil
		}
		return jsonHTTPResponse(200, nil, `{
			"access_token":"a1",
			"refresh_token":"r1",
			"expires_in":3600,
			"scope":"https://www.googleapis.com/auth/userinfo.email"
		}`), nil
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	mgr := newTestManager(t, makeFakeConfig(), stateDir, newFakeClock(), rt)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = mgr.Login(ctx, fixedPort, func(authURL string) error {
		u, _ := url.Parse(authURL)
		redir := u.Query().Get("redirect_uri")
		if !strings.Contains(redir, fmt.Sprintf(":%d/CALLBACK_AUTH", fixedPort)) {
			t.Fatalf("expected fixed port %d in redirect_uri %q", fixedPort, redir)
		}
		go func() {
			_, _ = http.Get(redir + "?code=c1&state=" + u.Query().Get("state"))
		}()
		return nil
	})
	assertAuthCode(t, err, "missing_scope")
	if userinfoCalled.Load() {
		t.Fatalf("userinfo must not be called when mandatory scope missing")
	}
	if _, statErr := os.Stat(filepath.Join(stateDir, stateFilename)); !os.IsNotExist(statErr) {
		t.Fatalf("state file must not exist after missing_scope login rejection")
	}
}

func TestStoragePermissionsSymlinksAndExternalEdit(t *testing.T) {
	base := t.TempDir()
	stateDir := filepath.Join(base, "state")
	cfg := makeFakeConfig()
	stateFile := seedDiskState(t, stateDir, cfg, "refresh-v1")

	// 0644 file rejected
	if err := os.Chmod(stateFile, 0o644); err != nil {
		t.Fatal(err)
	}
	mgr := newTestManager(t, cfg, stateDir, newFakeClock(), nil)
	_, err := mgr.Status()
	assertAuthCode(t, err, "insecure_storage")

	// 0755 dir rejected
	if err := os.Chmod(stateFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = mgr.Status()
	assertAuthCode(t, err, "insecure_storage")
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Symlinked stateFile rejected on Status and Logout
	outside := filepath.Join(base, "outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(stateFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, stateFile); err != nil {
		t.Fatal(err)
	}
	_, err = mgr.Status()
	assertAuthCode(t, err, "insecure_storage")
	_, err = mgr.Logout()
	assertAuthCode(t, err, "insecure_storage")
	_ = os.Remove(stateFile)

	// Symlinked stateDir rejected
	symDir := filepath.Join(base, "symdir")
	if err := os.Symlink(stateDir, symDir); err != nil {
		t.Fatal(err)
	}
	symMgr := newTestManager(t, cfg, symDir, newFakeClock(), nil)
	_, err = symMgr.Status()
	assertAuthCode(t, err, "insecure_storage")
	_, err = symMgr.Logout()
	assertAuthCode(t, err, "insecure_storage")

	// External edit & deletion reload
	seedDiskState(t, stateDir, cfg, "refresh-v1")
	var seenRT []string
	var mu sync.Mutex
	clock := newFakeClock()
	mgr = newTestManager(t, cfg, stateDir, clock, func(req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		vals, _ := url.ParseQuery(string(b))
		mu.Lock()
		seenRT = append(seenRT, vals.Get("refresh_token"))
		mu.Unlock()
		return jsonHTTPResponse(200, nil, `{"access_token":"tok-from-refresh","expires_in":3600}`), nil
	})
	tok, err := mgr.AccessToken(context.Background(), "")
	if err != nil || tok != "tok-from-refresh" {
		t.Fatalf("unexpected AccessToken: %q %v", tok, err)
	}

	// External atomic replacement with different refresh token & mtime.
	clock.Advance(2 * time.Second)
	extTmp := filepath.Join(stateDir, "ext.tmp")
	raw, _ := json.Marshal(map[string]any{
		"version":         1,
		"client_id":       cfg.ClientID,
		"scopes":          cfg.Scopes,
		"account":         map[string]any{"email": "bob@example.com"},
		"refresh_token":   "refresh-external",
		"reauth_required": false,
		"updated_at":      "2026-11-20T02:00:00Z",
	})
	_ = os.WriteFile(extTmp, raw, 0o600)
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(extTmp, future, future)
	_ = os.Rename(extTmp, filepath.Join(stateDir, stateFilename))

	st, err := mgr.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Email == nil || *st.Email != "bob@example.com" || st.HasAccessToken {
		t.Fatalf("external edit did not invalidate/reload state: %+v", st)
	}
	_, err = mgr.AccessToken(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(seenRT) != 2 || seenRT[1] != "refresh-external" {
		t.Fatalf("expected external refresh token, got %v", seenRT)
	}

	// External deletion
	_ = os.Remove(filepath.Join(stateDir, stateFilename))
	st, err = mgr.Status()
	if err != nil || st.LoggedIn {
		t.Fatalf("expected logged out after external deletion: %+v %v", st, err)
	}
}

func TestSingleflightRejectedCooldownInvalidGrantAndLogout(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := makeFakeConfig()
	seedDiskState(t, stateDir, cfg, "rt-1")
	clock := newFakeClock()

	var gen atomic.Int32
	gate := make(chan struct{})
	var gateOnce sync.Once

	rt := func(req *http.Request) (*http.Response, error) {
		n := gen.Add(1)
		if n == 1 {
			<-gate
		}
		return jsonHTTPResponse(200, nil, fmt.Sprintf(`{"access_token":"tok-%d","expires_in":100,"refresh_token":"rt-%d"}`, n, n+1)), nil
	}

	mgr := newTestManager(t, cfg, stateDir, clock, rt)

	// 10 concurrent cold-start callers + 1 cancelled caller; cancelled caller must not fail others.
	const workers = 10
	results := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = mgr.AccessToken(context.Background(), "")
		}(i)
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancelErrCh := make(chan error, 1)
	go func() {
		_, err := mgr.AccessToken(cancelCtx, "")
		cancelErrCh <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-cancelErrCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled for cancelled waiter, got %v", err)
	}

	gateOnce.Do(func() { close(gate) })
	wg.Wait()

	for i := 0; i < workers; i++ {
		if errs[i] != nil || results[i] != "tok-1" {
			t.Fatalf("worker %d got %q %v", i, results[i], errs[i])
		}
	}
	if gen.Load() != 1 {
		t.Fatalf("expected 1 singleflight refresh, got %d", gen.Load())
	}

	// Verify rotated refresh token persisted by restarting Manager.
	mgr2 := newTestManager(t, cfg, stateDir, clock, func(req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		vals, _ := url.ParseQuery(string(b))
		if vals.Get("refresh_token") != "rt-2" {
			return jsonHTTPResponse(400, nil, `{"error":"invalid_grant"}`), nil
		}
		return jsonHTTPResponse(200, nil, `{"access_token":"tok-restarted","expires_in":100}`), nil
	})
	tokR, err := mgr2.AccessToken(context.Background(), "")
	if err != nil || tokR != "tok-restarted" {
		t.Fatalf("expected rotated refresh token rt-2 to work after restart: %q %v", tokR, err)
	}

	// 30s margin check on mgr.
	clock.Advance(69 * time.Second) // 31s remaining -> cached
	tokCached, err := mgr.AccessToken(context.Background(), "")
	if err != nil || tokCached != "tok-1" || gen.Load() != 1 {
		t.Fatalf("expected cached tok-1 at 31s remaining, got %q %v (gen=%d)", tokCached, err, gen.Load())
	}
	clock.Advance(1 * time.Second) // 30s remaining -> refreshes
	tokNext, err := mgr.AccessToken(context.Background(), "")
	if err != nil || tokNext != "tok-2" || gen.Load() != 2 {
		t.Fatalf("expected refreshed tok-2 at 30s remaining, got %q %v (gen=%d)", tokNext, err, gen.Load())
	}

	// Concurrent unary rejected token force refresh without stampede.
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = mgr.AccessToken(context.Background(), "tok-2")
		}(i)
	}
	wg.Wait()
	for i := 0; i < workers; i++ {
		if errs[i] != nil || results[i] != "tok-3" {
			t.Fatalf("rejected worker %d got %q %v", i, results[i], errs[i])
		}
	}
	if gen.Load() != 3 {
		t.Fatalf("expected single forced refresh (gen=3), got %d", gen.Load())
	}

	// Stale rejected="tok-2" does not refresh again.
	tokStale, err := mgr.AccessToken(context.Background(), "tok-2")
	if err != nil || tokStale != "tok-3" || gen.Load() != 3 {
		t.Fatalf("stale rejection caused extra refresh: %q %v gen=%d", tokStale, err, gen.Load())
	}

	// Transient 503 with Retry-After: inf -> finite backoff cooldown, recovers after cooldown.
	var flakyCalls atomic.Int32
	flakyMgr := newTestManager(t, cfg, stateDir, clock, func(req *http.Request) (*http.Response, error) {
		if flakyCalls.Add(1) == 1 {
			return jsonHTTPResponse(503, map[string]string{"Retry-After": "inf"}, `{"error":"temporarily_unavailable"}`), nil
		}
		return jsonHTTPResponse(200, nil, `{"access_token":"tok-recovered","expires_in":3600}`), nil
	})
	_, err = flakyMgr.AccessToken(context.Background(), "")
	ae := assertAuthCode(t, err, "transient_error")
	if ae.RetryAfter <= 0 || ae.RetryAfter > maxCooldown {
		t.Fatalf("unexpected RetryAfter: %v", ae.RetryAfter)
	}
	_, err = flakyMgr.AccessToken(context.Background(), "")
	assertAuthCode(t, err, "transient_cooldown")
	if flakyCalls.Load() != 1 {
		t.Fatalf("expected cooldown to short-circuit HTTP call")
	}
	clock.Advance(ae.RetryAfter)
	tokRec, err := flakyMgr.AccessToken(context.Background(), "")
	if err != nil || tokRec != "tok-recovered" {
		t.Fatalf("expected recovery after cooldown, got %q %v", tokRec, err)
	}

	// invalid_grant sanitizes error and persists reauth_required=true.
	var igCalls atomic.Int32
	igMgr := newTestManager(t, cfg, stateDir, clock, func(req *http.Request) (*http.Response, error) {
		igCalls.Add(1)
		return jsonHTTPResponse(400, nil, `{"error":"invalid_grant","error_description":"LEAK_SECRET https://internal.invalid/tok"}`), nil
	})
	_, err = igMgr.AccessToken(context.Background(), "")
	ae = assertAuthCode(t, err, "invalid_grant")
	if strings.Contains(ae.Error(), "LEAK_SECRET") || strings.Contains(ae.Error(), "internal.invalid") {
		t.Fatalf("error message leaked upstream description: %q", ae.Error())
	}
	_, err = igMgr.AccessToken(context.Background(), "")
	assertAuthCode(t, err, "reauth_required")
	if igCalls.Load() != 1 {
		t.Fatalf("expected no HTTP call after invalid_grant")
	}

	// Logout clears local state without remote HTTP calls.
	var remoteCalled atomic.Bool
	loMgr := newTestManager(t, cfg, stateDir, clock, func(req *http.Request) (*http.Response, error) {
		remoteCalled.Store(true)
		return jsonHTTPResponse(200, nil, `{}`), nil
	})
	hadSession, err := loMgr.Logout()
	if err != nil || !hadSession {
		t.Fatalf("expected hadSession=true, err=nil; got %v %v", hadSession, err)
	}
	if remoteCalled.Load() {
		t.Fatalf("Logout must not call remote revocation")
	}
	hadAgain, err := loMgr.Logout()
	if err != nil || hadAgain {
		t.Fatalf("expected hadSession=false on second logout, got %v %v", hadAgain, err)
	}

	// Ensure invalid JSON Infinity expires_in fails cleanly.
	seedDiskState(t, stateDir, cfg, "rt-nan")
	nanMgr := newTestManager(t, cfg, stateDir, clock, func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(200, nil, `{"access_token":"tok","expires_in":0}`), nil
	})
	_, err = nanMgr.AccessToken(context.Background(), "")
	assertAuthCode(t, err, "invalid_token_response")

	// CheckRedirect blocks unexpected HTTP redirects.
	redirClient := newStrictHTTPClient()
	redirErr := redirClient.CheckRedirect(&http.Request{}, []*http.Request{{}})
	assertAuthCode(t, redirErr, "unexpected_redirect")

	// Verify JSON bytes match Status struct cleanly with no NaN.
	var buf bytes.Buffer
	st, err := mgr.Status()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(&buf).Encode(st); err != nil {
		t.Fatal(err)
	}
}

func TestAccountFromIDTokenValidation(t *testing.T) {
	cfg := makeFakeConfig()
	m := newTestManager(t, cfg, t.TempDir(), nil, nil)
	good := makeFakeIDToken(t, cfg, nil)
	account, err := m.accountFromIDToken(good)
	if err != nil || account.Email != "alice@example.com" || account.Subject == nil || *account.Subject != "sub-1" {
		t.Fatalf("valid ID token rejected: %+v %v", account, err)
	}
	for name, token := range map[string]string{
		"wrong-audience": makeFakeIDToken(t, cfg, map[string]any{"aud": "other.apps.googleusercontent.com"}),
		"wrong-issuer":   makeFakeIDToken(t, cfg, map[string]any{"iss": "https://evil.example"}),
		"unverified":     makeFakeIDToken(t, cfg, map[string]any{"email_verified": false}),
		"no-email":       makeFakeIDToken(t, cfg, map[string]any{"email": ""}),
		"malformed":      "not-a-jwt",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := m.accountFromIDToken(token); err == nil {
				t.Fatal("invalid ID token accepted")
			}
		})
	}
}

func TestBeginLoginCallbackParsingAndExpiry(t *testing.T) {
	clock := newFakeClock()
	cfg := makeFakeConfig()
	m := newTestManager(t, cfg, t.TempDir(), clock, nil)
	ctx := context.Background()

	if _, _, err := m.BeginLogin("http://evil.example/CALLBACK_AUTH"); err == nil {
		t.Fatal("non-loopback redirect accepted")
	}
	if _, _, err := m.BeginLogin("https://127.0.0.1:14535/CALLBACK_AUTH"); err == nil {
		t.Fatal("https loopback redirect accepted")
	}
	authURL, attempt, err := m.BeginLogin("http://127.0.0.1:14535/CALLBACK_AUTH")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("scope") != fstScope || q.Get("redirect_uri") != attempt.RedirectURI || q.Get("access_type") != "offline" ||
		q.Get("code_challenge_method") != "S256" || q.Get("state") != attempt.State {
		t.Fatalf("unexpected authorization URL parameters: %v", q)
	}
	if strings.Contains(authURL, cfg.ClientSecret) {
		t.Fatal("authorization URL leaked the client secret")
	}

	code, err := attempt.ParseCallback("http://127.0.0.1:14535/CALLBACK_AUTH?state=" + url.QueryEscape(attempt.State) + "&code=4%2Fabc")
	if err != nil || code != "4/abc" {
		t.Fatalf("callback parse: %q %v", code, err)
	}
	if _, err := attempt.ParseCallback("http://127.0.0.1:14535/CALLBACK_AUTH?state=wrong&code=4%2Fabc"); err == nil {
		t.Fatal("mismatched state accepted")
	}
	if code, err := attempt.ParseCallback("4/xyz"); err != nil || code != "4/xyz" {
		t.Fatalf("bare code rejected: %q %v", code, err)
	}
	if _, err := attempt.ParseCallback(""); err == nil {
		t.Fatal("empty callback accepted")
	}

	clock.Advance(16 * time.Minute)
	if _, err := m.CompleteLogin(ctx, attempt, "4/abc"); err == nil {
		t.Fatal("expired attempt accepted")
	} else if got := assertAuthCode(t, err, "attempt_expired"); got.Stage != StageAuthorization {
		t.Fatalf("expiry stage: %q", got.Stage)
	}
}

func TestCompleteLoginFromAdminSubmittedCallback(t *testing.T) {
	clock := newFakeClock()
	cfg := makeFakeConfig()
	stateDir := filepath.Join(t.TempDir(), "state")
	rt := func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != GoogleTokenURL {
			t.Fatalf("unexpected URL: %s", req.URL.String())
		}
		return jsonHTTPResponse(200, nil, `{
			"access_token":"admin-access",
			"refresh_token":"admin-refresh",
			"expires_in":3600,
			"scope":"openid https://www.googleapis.com/auth/aicode",
			"id_token":"`+makeFakeIDToken(t, cfg, nil)+`"
		}`), nil
	}
	m := newTestManager(t, cfg, stateDir, clock, rt)
	_, attempt, err := m.BeginLogin("http://127.0.0.1:14535/CALLBACK_AUTH")
	if err != nil {
		t.Fatal(err)
	}
	code, err := attempt.ParseCallback("http://127.0.0.1:14535/CALLBACK_AUTH?state=" + url.QueryEscape(attempt.State) + "&code=admin-code")
	if err != nil {
		t.Fatal(err)
	}
	st, err := m.CompleteLogin(context.Background(), attempt, code)
	if err != nil || !st.LoggedIn || st.Email == nil || *st.Email != "alice@example.com" {
		t.Fatalf("complete login: %+v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, stateFilename)); err != nil {
		t.Fatalf("state not persisted: %v", err)
	}
}

func TestStaleRefreshCannotOverwriteNewSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"success", 200, `{"access_token":"stale-access","refresh_token":"rotated-stale","expires_in":3600,"scope":"openid https://www.googleapis.com/auth/aicode"}`},
		{"invalid-grant", 400, `{"error":"invalid_grant"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := makeFakeConfig()
			dir := filepath.Join(t.TempDir(), "state")
			path := seedDiskState(t, dir, cfg, "old-refresh")
			m := newTestManager(t, cfg, dir, newFakeClock(), func(*http.Request) (*http.Response, error) {
				return jsonHTTPResponse(tc.status, nil, tc.body), nil
			})
			if _, err := m.Status(); err != nil {
				t.Fatal(err)
			}

			m.mu.Lock()
			staleGen := m.gen
			m.gen++ // simulate a completed new login
			m.mu.Unlock()

			_, err := m.executeRefreshHTTP("old-refresh", &persistedAccount{Email: "old@example.com"}, staleGen)
			assertAuthCode(t, err, "session_changed")

			m.mu.Lock()
			refreshToken, reauth := m.refreshToken, m.reauthRequired
			m.mu.Unlock()
			if refreshToken != "old-refresh" || reauth {
				t.Fatalf("stale refresh mutated the session: token=%q reauth=%v", refreshToken, reauth)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "rotated-stale") || strings.Contains(string(raw), `"reauth_required": true`) {
				t.Fatalf("stale refresh rewrote the persisted session: %s", raw)
			}
		})
	}
}

func TestParseCallbackRejectsMismatchedEndpoints(t *testing.T) {
	m := newTestManager(t, makeFakeConfig(), t.TempDir(), newFakeClock(), nil)
	_, attempt, err := m.BeginLogin("http://127.0.0.1:14535/CALLBACK_AUTH")
	if err != nil {
		t.Fatal(err)
	}
	state := url.QueryEscape(attempt.State)
	for name, raw := range map[string]string{
		"wrong-port":      "http://127.0.0.1:9999/CALLBACK_AUTH?state=" + state + "&code=4%2Fabc",
		"wrong-path":      "http://127.0.0.1:14535/other?state=" + state + "&code=4%2Fabc",
		"https":           "https://127.0.0.1:14535/CALLBACK_AUTH?state=" + state + "&code=4%2Fabc",
		"missing-state":   "http://127.0.0.1:14535/CALLBACK_AUTH?code=4%2Fabc",
		"duplicate-code":  "http://127.0.0.1:14535/CALLBACK_AUTH?state=" + state + "&code=a&code=b",
		"duplicate-state": "http://127.0.0.1:14535/CALLBACK_AUTH?state=" + state + "&state=" + state + "&code=4%2Fabc",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := attempt.ParseCallback(raw); err == nil {
				t.Fatalf("mismatched callback accepted: %s", raw)
			}
		})
	}
}

func TestLogoutInvalidatesInflightRefreshGeneration(t *testing.T) {
	cfg := makeFakeConfig()
	dir := filepath.Join(t.TempDir(), "state")
	seedDiskState(t, dir, cfg, "logout-refresh")
	m := newTestManager(t, cfg, dir, newFakeClock(), nil)
	if _, err := m.Status(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	before := m.gen
	m.mu.Unlock()
	if _, err := m.Logout(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	after := m.gen
	m.mu.Unlock()
	if after <= before {
		t.Fatalf("logout did not advance the session generation (%d -> %d)", before, after)
	}
}
