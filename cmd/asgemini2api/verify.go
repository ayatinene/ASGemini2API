package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/aicode"
	"github.com/ayatinene/ASGemini2API/internal/aicode/pb"
	"github.com/ayatinene/ASGemini2API/internal/chat"
	"github.com/ayatinene/ASGemini2API/internal/gateway"
	"github.com/ayatinene/ASGemini2API/internal/settings"
)

const (
	configCheck      = "FetchConfig"
	quotaBeforeCheck = "FetchQuotaStatus.before"
	generateCheck    = "StreamGenerateContent"
	quotaAfterCheck  = "FetchQuotaStatus.after"
)

// verificationError reports an insufficient response, not a gRPC status.
type verificationError struct {
	check, code, message string
}

func (e *verificationError) Error() string { return e.message }

// verificationCallError preserves the underlying error stage and adds the
// operation that failed, including whether a generation was already attempted.
type verificationCallError struct {
	check     string
	err       error
	attempted bool
}

func (e *verificationCallError) Error() string { return e.err.Error() }
func (e *verificationCallError) Unwrap() error { return e.err }

type quotaSnapshot struct {
	FetchedAt time.Time            `json:"fetched_at"`
	Buckets   []aicode.QuotaBucket `json:"buckets"`
}

type generationEvidence struct {
	Model          string `json:"model"`
	UpstreamFrames int    `json:"upstream_frames"`
	FinishReason   string `json:"finish_reason"`
	ExpectedReply  bool   `json:"expected_reply"`
}

type verification struct {
	Verified    bool                `json:"verified"`
	Models      []aicode.Model      `json:"models"`
	QuotaBefore quotaSnapshot       `json:"quota_before"`
	Generation  *generationEvidence `json:"generation,omitempty"`
	QuotaAfter  *quotaSnapshot      `json:"quota_after,omitempty"`
}

func verify(ctx context.Context, client gateway.Upstream, cfg settings.Config, out io.Writer, generate bool, modelID string) error {
	readTimeout := 3*cfg.UnaryTimeout + 20*time.Second
	lookupCtx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	response, err := client.FetchConfig(lookupCtx)
	if err != nil {
		return &verificationCallError{check: configCheck, err: err}
	}
	models := aicode.Models(response)
	if len(models) == 0 || models[0].Fallback {
		return &verificationError{configCheck, "no_discovered_models", "FetchConfig returned no chat-agent models; a local fallback is not verification"}
	}
	before, err := verifyQuota(lookupCtx, client, quotaBeforeCheck)
	if err != nil {
		return &verificationCallError{check: quotaBeforeCheck, err: err}
	}
	cancel()

	report := verification{Models: models, QuotaBefore: before}
	if generate {
		var selected *aicode.Model
		for _, model := range models {
			if modelID == "" || modelID == model.ID {
				selected = &model
				break
			}
		}
		if selected == nil {
			return errors.New("selected model is not in the active account's model list")
		}
		if knownExhausted(before.Buckets, selected.ID) {
			return &verificationError{quotaBeforeCheck, "observed_quota_exhausted", "a matching quota bucket has zero remaining fraction; no generation was attempted"}
		}
		generation, err := verifyGeneration(ctx, client, *selected)
		if err != nil {
			return err
		}
		report.Generation = &generation
		quotaCtx, stop := context.WithTimeout(ctx, readTimeout)
		defer stop()
		after, err := verifyQuota(quotaCtx, client, quotaAfterCheck)
		if err != nil {
			return &verificationCallError{check: quotaAfterCheck, err: err, attempted: true}
		}
		report.QuotaAfter = &after
	}
	report.Verified = true
	return jsonOutput(out, report)
}

func knownExhausted(buckets []aicode.QuotaBucket, modelID string) bool {
	for _, b := range buckets {
		matches := b.ModelID == modelID || (b.ModelID == "" && b.Type == "REQUESTS")
		if matches && b.RemainingFraction != nil && *b.RemainingFraction == 0 {
			return true
		}
	}
	return false
}

func verifyQuota(ctx context.Context, client gateway.Upstream, check string) (quotaSnapshot, error) {
	response, err := client.FetchQuota(ctx)
	if err != nil {
		return quotaSnapshot{}, err
	}
	buckets := aicode.Quota(response)
	for _, b := range buckets {
		if b.RemainingFraction != nil && (b.ModelID != "" || (b.Type != "QUOTA_TYPE_UNSPECIFIED" && !strings.HasPrefix(b.Type, "UNKNOWN_"))) {
			return quotaSnapshot{FetchedAt: time.Now().UTC(), Buckets: buckets}, nil
		}
	}
	return quotaSnapshot{}, &verificationError{check, "no_observed_quota", "FetchQuotaStatus returned no identifiable bucket with a valid remaining fraction"}
}

func verifyGeneration(ctx context.Context, client gateway.Upstream, model aicode.Model) (generationEvidence, error) {
	request, err := chat.Encode(&chat.Request{Model: model.ID, Messages: []chat.Message{{Role: "user", Content: "Reply with only the word OK."}}}, model, gateway.SessionID(), nil)
	if err != nil {
		return generationEvidence{}, err
	}
	accumulator := chat.NewCompletion(model.ID, false)
	frames := 0
	err = client.Stream(ctx, request, func(chunk *pb.GenerateContentResponse) error {
		frames++
		_, err := accumulator.Push(chunk)
		return err
	})
	if err != nil {
		return generationEvidence{}, &verificationCallError{check: generateCheck, err: err, attempted: true}
	}
	result, err := accumulator.Result()
	if err != nil || len(result.Choices) == 0 {
		return generationEvidence{}, &verificationCallError{
			check: generateCheck, attempted: true,
			err: &verificationError{generateCheck, "incomplete_generation", "the generation ended without a complete response; it was not replayed"},
		}
	}
	choice := result.Choices[0]
	text, _ := choice.Message.Content.(string)
	if choice.FinishReason != "stop" || strings.TrimSpace(text) != "OK" {
		return generationEvidence{}, &verificationCallError{
			check: generateCheck, attempted: true,
			err: &verificationError{generateCheck, "unexpected_generation", "the generation did not end normally with the expected test reply; it was not replayed"},
		}
	}
	return generationEvidence{Model: model.ID, UpstreamFrames: frames, FinishReason: choice.FinishReason, ExpectedReply: true}, nil
}
