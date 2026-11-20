package auth

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserAdmissionIsNotConsentOrTokenExchange(t *testing.T) {
	for _, tc := range []struct {
		providerCode, wantCode string
		stage                  Stage
	}{
		{"restricted_client", "restricted_client", StageClientAdmission},
		{"access_denied", "access_denied", StageAuthorization},
		{"SYNTHETIC_SECRET_VALUE", "authorization_failed", StageAuthorization},
	} {
		t.Run(tc.wantCode, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			m := newTestManager(t, makeFakeConfig(), dir, nil, func(*http.Request) (*http.Response, error) {
				t.Fatal("an error callback must never exchange a code")
				return nil, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			_, err := m.Login(ctx, 0, func(raw string) error {
				u, err := url.Parse(raw)
				if err != nil {
					return err
				}
				q := u.Query()
				p := url.Values{"state": {q.Get("state")}, "error": {tc.providerCode}, "error_description": {"NOT_FOR_LOGS"}}
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, q.Get("redirect_uri")+"?"+p.Encode(), nil)
				if err != nil {
					return err
				}
				r, err := http.DefaultClient.Do(request)
				if err != nil {
					return err
				}
				return r.Body.Close()
			})
			got := assertAuthCode(t, err, tc.wantCode)
			if got.Stage != tc.stage || strings.Contains(got.Error(), "NOT_FOR_LOGS") || strings.Contains(got.Error(), "SYNTHETIC_SECRET_VALUE") {
				t.Fatalf("incorrect stage or unexpected upstream diagnostic: %+v", got)
			}
			if _, err := os.Stat(filepath.Join(dir, stateFilename)); !os.IsNotExist(err) {
				t.Fatal("a rejected login must not write a grant")
			}
		})
	}
}

func TestCodeExchangeAcceptsOmittedScopeAndRejectsExplicitMismatch(t *testing.T) {
	for _, tc := range []struct{ name, scope, wantCode string }{
		{"omitted", "", ""},
		{"explicit-empty", `,"scope":""`, "missing_scope"},
		{"explicit-mismatch", `,"scope":"https://www.googleapis.com/auth/userinfo.email"`, "missing_scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t, makeFakeConfig(), t.TempDir(), nil, func(*http.Request) (*http.Response, error) {
				return jsonHTTPResponse(200, nil, `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","expires_in":3600`+tc.scope+`}`), nil
			})
			_, _, _, _, err := m.exchangeCode(context.Background(), "synthetic-code", "http://127.0.0.1:1234/", "synthetic-verifier")
			if tc.wantCode == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if got := assertAuthCode(t, err, tc.wantCode); got.Stage != StageCodeExchange {
				t.Fatalf("scope error belongs to code exchange, got %q", got.Stage)
			}
		})
	}
}

func TestExchangeAndRefreshStagesPreserveClientError(t *testing.T) {
	cfg := makeFakeConfig()
	dir := filepath.Join(t.TempDir(), "state")
	path := seedDiskState(t, dir, cfg, "existing-refresh-token")
	var calls atomic.Int32
	m := newTestManager(t, cfg, dir, nil, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return jsonHTTPResponse(401, nil, `{"error":"invalid_client","error_description":"NOT_FOR_LOGS"}`), nil
	})
	_, _, _, _, err := m.exchangeCode(context.Background(), "fake-code", "http://127.0.0.1:1234/", "fake-verifier")
	if got := assertAuthCode(t, err, "invalid_client"); got.Stage != StageCodeExchange || strings.Contains(got.Message, "NOT_FOR_LOGS") {
		t.Fatalf("unexpected code-exchange error: %+v", got)
	}
	_, err = m.AccessToken(context.Background(), "")
	if got := assertAuthCode(t, err, "invalid_client"); got.Stage != StageRefresh {
		t.Fatalf("unexpected refresh error: %+v", got)
	}
	if status, err := m.Status(); err != nil || status.ClientConfigError != "invalid_client" || status.ReauthRequired {
		t.Fatalf("incorrect local session state after registration failure: %+v, %v", status, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "existing-refresh-token") {
		t.Fatal("client registration failure must not erase the existing grant")
	}
	_, err = m.AccessToken(context.Background(), "")
	assertAuthCode(t, err, "invalid_client")
	if calls.Load() != 2 {
		t.Fatalf("registration rejection should not retry; got %d calls (exchange + one refresh expected)", calls.Load())
	}
}

func TestFlexibleScopeExpansionSatisfiesRequestedScope(t *testing.T) {
	cfg := makeFakeConfig()
	m := newTestManager(t, cfg, t.TempDir(), nil, func(*http.Request) (*http.Response, error) {
		return jsonHTTPResponse(200, nil, `{"access_token":"a","refresh_token":"r","expires_in":3600,"scope":"openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/aicode"}`), nil
	})
	if _, _, _, _, err := m.exchangeCode(context.Background(), "c", "http://127.0.0.1:1234/", "v"); err != nil {
		t.Fatalf("expanded flexible bundle rejected: %v", err)
	}
}
