package aicode

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/aicode/pb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestModelsFilteringDeduplicationAndKnownThinking(t *testing.T) {
	// Nil response must not fabricate fallback models.
	if got := Models(nil); got != nil {
		t.Fatalf("expected nil for nil FetchConfigResponse, got %+v", got)
	}

	// Empty / non-matching response returns fallback after successful config call.
	emptyFallback := Models(&pb.FetchConfigResponse{
		AvailableExperiences: []*pb.FetchConfigResponse_Experience{
			{
				Name:  "code_completion/exp1",
				Model: &pb.FetchConfigResponse_Model{ModelId: "completion-only"},
			},
		},
	})
	if len(emptyFallback) != 1 || !emptyFallback[0].Fallback || emptyFallback[0].ID != "studio-default" {
		t.Fatalf("expected single studio-default fallback, got %+v", emptyFallback)
	}

	// Verify empty slices serialize as JSON arrays [], not null.
	rawFallback, err := json.Marshal(emptyFallback[0])
	if err != nil {
		t.Fatalf("marshal fallback: %v", err)
	}
	var fallbackMap map[string]any
	if err := json.Unmarshal(rawFallback, &fallbackMap); err != nil {
		t.Fatalf("unmarshal fallback: %v", err)
	}
	if _, ok := fallbackMap["thinking_levels"].([]any); !ok {
		t.Fatalf("expected thinking_levels JSON array, got %T", fallbackMap["thinking_levels"])
	}
	if _, ok := fallbackMap["features"].([]any); !ok {
		t.Fatalf("expected features JSON array, got %T", fallbackMap["features"])
	}

	// Normal filtering, deduplication, and thinking level preservation (EXTRA_HIGH & UNSPECIFIED excluded).
	resp := &pb.FetchConfigResponse{
		AvailableExperiences: []*pb.FetchConfigResponse_Experience{
			{
				Name:  "other_mode/ignored",
				Model: &pb.FetchConfigResponse_Model{ModelId: "ignored-model"},
			},
			{
				Name: "chat_agent_mode/primary",
				Model: &pb.FetchConfigResponse_Model{
					ModelId:          "gemini-test",
					DisplayName:      "Gemini Test",
					InputTokenLimit:  proto.Int32(1048576),
					OutputTokenLimit: proto.Int32(65536),
					SupportedThinkingLevels: []pb.FetchConfigResponse_ThinkingConfig_ThinkingLevel{
						pb.FetchConfigResponse_ThinkingConfig_THINKING_LEVEL_UNSPECIFIED,
						pb.FetchConfigResponse_ThinkingConfig_HIGH,
						pb.FetchConfigResponse_ThinkingConfig_EXTRA_HIGH,
						pb.FetchConfigResponse_ThinkingConfig_LOW,
						pb.FetchConfigResponse_ThinkingConfig_ThinkingLevel(99),
					},
					SupportedFeatures: []pb.FetchConfigResponse_Model_Feature{
						pb.FetchConfigResponse_Model_FUNCTION_CALLING,
						pb.FetchConfigResponse_Model_THINKING_LEVEL,
					},
				},
			},
			{
				Name: "chat_agent_mode/duplicate",
				Model: &pb.FetchConfigResponse_Model{
					ModelId:     "gemini-test",
					DisplayName: "Duplicate Should Be Skipped",
				},
			},
			{
				Name: "chat_agent_mode/secondary",
				Model: &pb.FetchConfigResponse_Model{
					ModelId:          "gemini-lite",
					Name:             "models/gemini-lite",
					InputTokenLimit:  proto.Int32(0),
					OutputTokenLimit: proto.Int32(-1),
				},
			},
		},
	}

	models := Models(resp)
	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d: %+v", len(models), models)
	}
	if models[0].ID != "gemini-test" || models[0].Experience != "chat_agent_mode/primary" ||
		models[0].DisplayName != "Gemini Test" || models[0].InputTokenLimit != 1048576 ||
		models[0].OutputTokenLimit != 65536 || models[0].Fallback {
		t.Fatalf("unexpected primary model: %+v", models[0])
	}
	if len(models[0].ThinkingLevels) != 2 || models[0].ThinkingLevels[0] != "low" || models[0].ThinkingLevels[1] != "high" {
		t.Fatalf("expected canonical known thinking levels [low high], got %v", models[0].ThinkingLevels)
	}
	if len(models[0].Features) != 2 || models[0].Features[0] != "FUNCTION_CALLING" || models[0].Features[1] != "THINKING_LEVEL" {
		t.Fatalf("unexpected features: %v", models[0].Features)
	}
	if models[1].ID != "gemini-lite" || models[1].DisplayName != "models/gemini-lite" ||
		models[1].InputTokenLimit != 0 || models[1].OutputTokenLimit != 0 {
		t.Fatalf("unexpected secondary model: %+v", models[1])
	}
}

func TestQuotaMappingAndInvalidHandling(t *testing.T) {
	if got := Quota(nil); got != nil {
		t.Fatalf("expected nil for nil FetchQuotaStatusResponse, got %+v", got)
	}

	resetTS := time.Date(2026, 11, 20, 15, 0, 0, 0, time.UTC)
	resp := &pb.FetchQuotaStatusResponse{
		Buckets: []*pb.FetchQuotaStatusResponse_BucketInfo{
			{
				RemainingFraction: 0.85,
				ResetTime:         timestamppb.New(resetTS),
				QuotaType:         pb.FetchQuotaStatusResponse_REQUESTS,
				Model: &pb.Model{
					ModelId:     "gemini-test",
					DisplayName: "Gemini Test",
				},
			},
			{
				RemainingFraction: float32(math.NaN()),
				QuotaType:         pb.FetchQuotaStatusResponse_QuotaType(42),
				Model:             &pb.Model{ModelId: "nan-model"},
			},
			{
				RemainingFraction: 1.5,
				Model:             &pb.Model{ModelId: "over-one"},
			},
			{
				RemainingFraction: -0.2,
				Model:             &pb.Model{ModelId: "negative"},
			},
		},
	}

	buckets := Quota(resp)
	if len(buckets) != 4 {
		t.Fatalf("expected 4 quota buckets, got %d", len(buckets))
	}
	if buckets[0].ModelID != "gemini-test" || buckets[0].DisplayName != "Gemini Test" ||
		buckets[0].Type != "REQUESTS" || buckets[0].RemainingFraction == nil ||
		math.Abs(*buckets[0].RemainingFraction-0.85) > 1e-6 ||
		buckets[0].ResetTime == nil || !buckets[0].ResetTime.Equal(resetTS) {
		t.Fatalf("unexpected first quota bucket: %+v", buckets[0])
	}
	if buckets[1].Type != "UNKNOWN_42" || buckets[1].RemainingFraction != nil || buckets[1].ResetTime != nil {
		t.Fatalf("expected nil RemainingFraction and UNKNOWN_42 for NaN bucket: %+v", buckets[1])
	}
	if buckets[2].RemainingFraction != nil || buckets[3].RemainingFraction != nil {
		t.Fatalf("expected out-of-range fractions to be nil: %+v %+v", buckets[2], buckets[3])
	}
}
