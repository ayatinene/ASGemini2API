package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/ayatinene/ASGemini2API/internal/aicode"
	"github.com/ayatinene/ASGemini2API/internal/aicode/pb"
	"github.com/ayatinene/ASGemini2API/internal/settings"
	"google.golang.org/grpc/codes"
)

type verifyUpstream struct {
	config        *pb.FetchConfigResponse
	configErr     error
	quotas        []*pb.FetchQuotaStatusResponse
	frames        []*pb.GenerateContentResponse
	quotaCalls    int
	generateCalls int
}

func (u *verifyUpstream) FetchConfig(context.Context) (*pb.FetchConfigResponse, error) {
	return u.config, u.configErr
}

func (u *verifyUpstream) FetchQuota(context.Context) (*pb.FetchQuotaStatusResponse, error) {
	call := u.quotaCalls
	u.quotaCalls++
	if call < len(u.quotas) {
		return u.quotas[call], nil
	}
	return &pb.FetchQuotaStatusResponse{}, nil
}

func (u *verifyUpstream) Stream(_ context.Context, _ *pb.GenerateContentRequest, yield func(*pb.GenerateContentResponse) error) error {
	u.generateCalls++
	for _, frame := range u.frames {
		if err := yield(frame); err != nil {
			return err
		}
	}
	return nil
}

func TestVerifyRequiresActualUpstreamEvidence(t *testing.T) {
	config := &pb.FetchConfigResponse{AvailableExperiences: []*pb.FetchConfigResponse_Experience{{
		Name: "chat_agent_mode_example", Model: &pb.FetchConfigResponse_Model{ModelId: "example"},
	}}}
	quota := func(value float32) *pb.FetchQuotaStatusResponse {
		return &pb.FetchQuotaStatusResponse{Buckets: []*pb.FetchQuotaStatusResponse_BucketInfo{{
			Model: &pb.Model{ModelId: "example"}, QuotaType: pb.FetchQuotaStatusResponse_REQUESTS, RemainingFraction: value,
		}}}
	}
	frame := func(text string, reason pb.FinishReason) []*pb.GenerateContentResponse {
		return []*pb.GenerateContentResponse{{Candidates: []*pb.Candidate{{
			Content:      &pb.Content{Role: "model", Parts: []*pb.Part{{Data: &pb.Part_Text{Text: text}}}},
			FinishReason: reason,
		}}}}
	}
	for _, tc := range []struct {
		name          string
		upstream      verifyUpstream
		generate      bool
		wantCode      string
		wantCheck     string
		quotaCalls    int
		generateCalls int
	}{
		{"unary permission denied", verifyUpstream{configErr: &aicode.Error{Code: codes.PermissionDenied}}, false, "PermissionDenied", configCheck, 0, 0},
		{"unary timeout", verifyUpstream{configErr: &aicode.Error{Code: codes.DeadlineExceeded}}, false, "DeadlineExceeded", configCheck, 0, 0},
		{"fallback only", verifyUpstream{config: &pb.FetchConfigResponse{}}, true, "no_discovered_models", configCheck, 0, 0},
		{"no buckets", verifyUpstream{config: config}, true, "no_observed_quota", quotaBeforeCheck, 1, 0},
		{"empty bucket", verifyUpstream{config: config, quotas: []*pb.FetchQuotaStatusResponse{{Buckets: []*pb.FetchQuotaStatusResponse_BucketInfo{{}}}}}, false, "no_observed_quota", quotaBeforeCheck, 1, 0},
		{"NaN quota", verifyUpstream{config: config, quotas: []*pb.FetchQuotaStatusResponse{quota(float32(math.NaN()))}}, true, "no_observed_quota", quotaBeforeCheck, 1, 0},
		{"exhausted", verifyUpstream{config: config, quotas: []*pb.FetchQuotaStatusResponse{quota(0)}}, true, "observed_quota_exhausted", quotaBeforeCheck, 1, 0},
		{"read only", verifyUpstream{config: config, quotas: []*pb.FetchQuotaStatusResponse{quota(0)}}, false, "", "", 1, 0},
		{"no semantic end", verifyUpstream{config: config, quotas: []*pb.FetchQuotaStatusResponse{quota(1)}}, true, "incomplete_generation", generateCheck, 1, 1},
		{"truncated", verifyUpstream{config: config, quotas: []*pb.FetchQuotaStatusResponse{quota(1)}, frames: frame("OK", pb.FinishReason_MAX_TOKENS)}, true, "unexpected_generation", generateCheck, 1, 1},
		{"wrong answer", verifyUpstream{config: config, quotas: []*pb.FetchQuotaStatusResponse{quota(1)}, frames: frame("NO", pb.FinishReason_STOP)}, true, "unexpected_generation", generateCheck, 1, 1},
		{"no quota after generation", verifyUpstream{config: config, quotas: []*pb.FetchQuotaStatusResponse{quota(1)}, frames: frame("OK", pb.FinishReason_STOP)}, true, "no_observed_quota", quotaAfterCheck, 2, 1},
		{"generation and quota snapshots", verifyUpstream{config: config, quotas: []*pb.FetchQuotaStatusResponse{quota(1), quota(0.5)}, frames: frame("OK", pb.FinishReason_STOP)}, true, "", "", 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := verify(context.Background(), &tc.upstream, settings.Config{}, &output, tc.generate, "")
			if tc.upstream.quotaCalls != tc.quotaCalls || tc.upstream.generateCalls != tc.generateCalls {
				t.Fatalf("unexpected calls: quota=%d generation=%d", tc.upstream.quotaCalls, tc.upstream.generateCalls)
			}
			if tc.wantCode == "" {
				var result verification
				if err != nil || json.Unmarshal(output.Bytes(), &result) != nil || !result.Verified || (result.Generation != nil) != tc.generate || (result.QuotaAfter != nil) != tc.generate {
					t.Fatalf("expected one complete success report, got %v %s", err, &output)
				}
				return
			}
			if err == nil || output.Len() != 0 {
				t.Fatalf("failed check emitted success output: %v %s", err, &output)
			}
			var diagnostic bytes.Buffer
			reportError(&diagnostic, err)
			var result struct {
				Error struct{ Code, Stage, Check string }
			}
			if err := json.Unmarshal(diagnostic.Bytes(), &result); err != nil || result.Error.Code != tc.wantCode || result.Error.Check != tc.wantCheck {
				t.Fatalf("unexpected verification diagnostic: %s", &diagnostic)
			}
			if strings.Contains(diagnostic.String(), `"generation_attempted": true`) != (tc.generateCalls > 0) {
				t.Fatalf("incorrect generation-attempt evidence: %s", &diagnostic)
			}
		})
	}
}
