package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/aicode/pb"
	"github.com/ayatinene/ASGemini2API/internal/auth"
	"github.com/ayatinene/ASGemini2API/internal/settings"
)

func TestAdminOAuthConsoleAndFlow(t *testing.T) {
	handler := testServer(&testUpstream{}, false)

	page := request(handler, http.MethodGet, "/admin/oauth", "", "")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Google 授权") {
		t.Fatalf("console page: %d %s", page.Code, page.Body.String()[:80])
	}
	if page.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("console page missing CSP")
	}

	if got := request(handler, http.MethodPost, "/admin/oauth/start", "", "{}"); got.Code != http.StatusUnauthorized {
		t.Fatalf("start without admin key: %d", got.Code)
	}

	start := request(handler, http.MethodPost, "/admin/oauth/start", testAdmin, "{}")
	if start.Code != http.StatusOK {
		t.Fatalf("start: %d %s", start.Code, start.Body.String())
	}
	var started oauthStartResult
	if err := json.Unmarshal(start.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(started.AuthURL, "state=test-state") || started.RedirectURI != "http://127.0.0.1:14535/CALLBACK_AUTH" || started.ExpiresIn <= 0 {
		t.Fatalf("unexpected start result: %+v", started)
	}

	again := request(handler, http.MethodPost, "/admin/oauth/start", testAdmin, "{}")
	var reused oauthStartResult
	_ = json.Unmarshal(again.Body.Bytes(), &reused)
	if !reused.Reused || reused.AuthURL != started.AuthURL {
		t.Fatalf("second start should reuse the pending attempt: %+v", reused)
	}

	if got := request(handler, http.MethodPost, "/admin/oauth/complete", "", `{"callback_url":"http://127.0.0.1:14535/CALLBACK_AUTH?state=test-state&code=test-code"}`); got.Code != http.StatusUnauthorized {
		t.Fatalf("complete without admin key: %d", got.Code)
	}
	badState := request(handler, http.MethodPost, "/admin/oauth/complete", testAdmin, `{"callback_url":"http://127.0.0.1:14535/CALLBACK_AUTH?state=wrong&code=test-code"}`)
	if badState.Code != http.StatusBadRequest || !strings.Contains(badState.Body.String(), "state_mismatch") {
		t.Fatalf("bad state should fail: %d %s", badState.Code, badState.Body.String())
	}

	done := request(handler, http.MethodPost, "/admin/oauth/complete", testAdmin, `{"callback_url":"http://127.0.0.1:14535/CALLBACK_AUTH?state=test-state&code=test-code"}`)
	if done.Code != http.StatusOK || !strings.Contains(done.Body.String(), `"logged_in":true`) {
		t.Fatalf("complete: %d %s", done.Code, done.Body.String())
	}

	after := request(handler, http.MethodPost, "/admin/oauth/complete", testAdmin, `{"code":"test-code"}`)
	if after.Code != http.StatusConflict || !strings.Contains(after.Body.String(), "no_pending_login") {
		t.Fatalf("pending attempt should be cleared: %d %s", after.Code, after.Body.String())
	}
}

type failingLoginAccount struct{ testAccount }

func (failingLoginAccount) BeginLogin(string) (string, *auth.LoginAttempt, error) {
	return "", nil, &auth.Error{Code: "oauth_client_not_configured", Message: "configure the local OAuth Desktop client file"}
}

func TestAdminOAuthStartReportsAuthErrors(t *testing.T) {
	cfg := settings.Config{CatalogTTL: time.Hour, QuotaTTL: time.Minute, MaxInFlight: 2, MaxBodyBytes: 4096}
	keys := settings.Keys{API: sha256.Sum256([]byte(testAPI)), Admin: sha256.Sum256([]byte(testAdmin))}
	handler := New(&testUpstream{}, failingLoginAccount{}, cfg, keys, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
	got := request(handler, http.MethodPost, "/admin/oauth/start", testAdmin, "{}")
	if got.Code != http.StatusBadGateway || !strings.Contains(got.Body.String(), "oauth_client_not_configured") {
		t.Fatalf("unexpected response: %d %s", got.Code, got.Body.String())
	}
}

type countingAccount struct {
	testAccount
	completes int
	beginErr  error
}

func (a *countingAccount) BeginLogin(redirectURI string) (string, *auth.LoginAttempt, error) {
	if a.beginErr != nil {
		return "", nil, a.beginErr
	}
	return a.testAccount.BeginLogin(redirectURI)
}

func (a *countingAccount) CompleteLogin(ctx context.Context, attempt *auth.LoginAttempt, code string) (auth.Status, error) {
	a.completes++
	return a.testAccount.CompleteLogin(ctx, attempt, code)
}

func TestAdminOAuthRejectsMismatchedCallbackWithoutExchange(t *testing.T) {
	account := &countingAccount{}
	cfg := settings.Config{CatalogTTL: time.Hour, QuotaTTL: time.Minute, MaxInFlight: 2, MaxBodyBytes: 4096}
	keys := settings.Keys{API: sha256.Sum256([]byte(testAPI)), Admin: sha256.Sum256([]byte(testAdmin))}
	handler := New(&testUpstream{}, account, cfg, keys, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()

	if got := request(handler, http.MethodPost, "/admin/oauth/start", testAdmin, "{}"); got.Code != http.StatusOK {
		t.Fatalf("start: %d %s", got.Code, got.Body.String())
	}
	cases := []struct{ name, body string }{
		{"wrong-host", `{"callback_url":"http://127.0.0.1:9999/CALLBACK_AUTH?state=test-state&code=test-code"}`},
		{"missing-state", `{"callback_url":"http://127.0.0.1:14535/CALLBACK_AUTH?code=test-code"}`},
		{"trailing-json", `{"callback_url":"http://127.0.0.1:14535/CALLBACK_AUTH?state=test-state&code=test-code"} {}`},
		{"oversized", `{"callback_url":"` + strings.Repeat("a", maxCallbackBytes) + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := request(handler, http.MethodPost, "/admin/oauth/complete", testAdmin, tc.body)
			if got.Code != http.StatusBadRequest && got.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("unexpected status: %d %s", got.Code, got.Body.String())
			}
			if account.completes != 0 {
				t.Fatalf("code exchange must not run for %s", tc.name)
			}
		})
	}

	bad := request(handler, http.MethodPost, "/admin/oauth/complete", testAdmin, `{"callback_url":"http://127.0.0.1:14535/CALLBACK_AUTH?state=test-state&code=wrong"}`)
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "missing_code") || account.completes != 1 {
		t.Fatalf("unexpected failed exchange: %d %s completes=%d", bad.Code, bad.Body.String(), account.completes)
	}
	good := request(handler, http.MethodPost, "/admin/oauth/complete", testAdmin, `{"callback_url":"http://127.0.0.1:14535/CALLBACK_AUTH?state=test-state&code=test-code"}`)
	if good.Code != http.StatusOK || account.completes != 2 {
		t.Fatalf("pending attempt should survive a failed exchange: %d %s completes=%d", good.Code, good.Body.String(), account.completes)
	}
}

func TestAccountSwitchClearsCachesAndCooldowns(t *testing.T) {
	cfg := settings.Config{CatalogTTL: time.Hour, QuotaTTL: time.Minute, MaxInFlight: 2, MaxBodyBytes: 4096}
	keys := settings.Keys{API: sha256.Sum256([]byte(testAPI)), Admin: sha256.Sum256([]byte(testAdmin))}
	upstream := &testUpstream{}
	server := New(upstream, testAccount{true}, cfg, keys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := server.models.get(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if server.models.latest().FetchedAt.IsZero() {
		t.Fatal("model cache was not populated")
	}
	server.mu.Lock()
	server.globalUntil = time.Now().Add(time.Hour)
	server.modelUntil["sample"] = time.Now().Add(time.Hour)
	server.mu.Unlock()

	server.invalidateAccountCaches()

	if !server.models.latest().FetchedAt.IsZero() {
		t.Fatal("model cache survived account switch")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if !server.globalUntil.IsZero() || len(server.modelUntil) != 0 {
		t.Fatalf("cooldowns survived account switch: global=%v models=%v", server.globalUntil, server.modelUntil)
	}
}

func TestAccountSwitchClearsHistory(t *testing.T) {
	cfg := settings.Config{CatalogTTL: time.Hour, QuotaTTL: time.Minute, MaxInFlight: 2, MaxBodyBytes: 4096}
	keys := settings.Keys{API: sha256.Sum256([]byte(testAPI)), Admin: sha256.Sum256([]byte(testAdmin))}
	server := New(&testUpstream{}, testAccount{true}, cfg, keys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	key := turnKey{1, 2, 3}
	server.cacheHistory.store(key, &pb.Content{Parts: []*pb.Part{{Data: &pb.Part_Text{Text: "old-account"}}}})
	if server.cacheHistory.lookup(key) == nil {
		t.Fatal("history was not stored")
	}
	server.invalidateAccountCaches()
	if got := server.cacheHistory.lookup(key); got != nil {
		t.Fatal("history survived an account switch")
	}
}
