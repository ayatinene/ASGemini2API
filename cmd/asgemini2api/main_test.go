package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ayatinene/ASGemini2API/internal/aicode"
	"github.com/ayatinene/ASGemini2API/internal/auth"
	"google.golang.org/grpc/codes"
)

func TestOAuthCommandsSeparateLocalConfigFromAdmission(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASGEMINI_OAUTH_CLIENT_FILE", "")
	args := []string{"--state-dir", filepath.Join(dir, "state"), "--input-dir", dir}
	var output, diagnostics bytes.Buffer
	invoke := func(command string) error {
		output.Reset()
		return run(context.Background(), append(args, command), &output, &diagnostics)
	}
	if err := invoke("status"); err != nil || !strings.Contains(output.String(), `"client_config_error": "oauth_client_not_configured"`) {
		t.Fatalf("status before configuring a client: %s, %v", &output, err)
	}
	if err := invoke("login"); err == nil {
		t.Fatal("unconfigured login should fail")
	} else {
		var e *auth.Error
		if !errors.As(err, &e) || e.Stage != auth.StageClientConfig {
			t.Fatalf("unexpected missing client error: %v", err)
		}
	}
	if diagnostics.Len() != 0 {
		t.Fatal("unconfigured login printed a browser URL")
	}
	if err := invoke("logout"); err != nil || !strings.Contains(output.String(), `"had_session": false`) {
		t.Fatalf("logout without a client: %s, %v", &output, err)
	}
	fixture := `{"installed":{"client_id":"fake-client.apps.googleusercontent.com","client_secret":"SYNTHETIC_SECRET_VALUE"}}`
	if err := os.WriteFile(filepath.Join(dir, "oauth-client.json"), []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := invoke("check-inputs"); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Valid     bool   `json:"valid_config"`
		Admission string `json:"google_client_admission"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || !result.Valid || result.Admission != "not_checked" {
		t.Fatalf("configuration check implied upstream success: %s", &output)
	}
	if out := output.String(); strings.Contains(out, "SYNTHETIC_SECRET_VALUE") || strings.Contains(out, "fake-client.apps.googleusercontent.com") {
		t.Fatal("configuration check exposed application registration details")
	}
}

func TestReportErrorSeparatesOAuthFromAiCode(t *testing.T) {
	for _, tc := range []struct {
		err             error
		wantStage, code string
	}{
		{&auth.Error{Code: "restricted_client", Stage: auth.StageClientAdmission, Message: "registration rejected"}, "oauth_client_admission", "restricted_client"},
		{&aicode.Error{Code: codes.PermissionDenied, RPC: "FetchConfig"}, "aicode_rpc", "PermissionDenied"},
	} {
		var output bytes.Buffer
		reportError(&output, tc.err)
		var result struct {
			Error struct{ Stage, Code string }
		}
		if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Error.Stage != tc.wantStage || result.Error.Code != tc.code {
			t.Fatalf("unexpected report %s: %v", &output, err)
		}
	}
}
