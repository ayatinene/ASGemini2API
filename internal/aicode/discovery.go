package aicode

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/aicode/pb"
)

// ChatAgentExperiencePrefix is the experience prefix selected by Android Studio's AiCodeModelApiProvider.
const ChatAgentExperiencePrefix = "chat_agent_mode"

// Model represents a discovered AiCode chat-agent model entry.
type Model struct {
	ID               string   `json:"id"`
	Experience       string   `json:"experience"`
	DisplayName      string   `json:"display_name"`
	InputTokenLimit  int      `json:"input_token_limit,omitempty"`
	OutputTokenLimit int      `json:"output_token_limit,omitempty"`
	ThinkingLevels   []string `json:"thinking_levels"`
	Features         []string `json:"features"`
	Fallback         bool     `json:"fallback"`
}

// QuotaBucket represents a single model quota bucket returned by FetchQuotaStatus.
type QuotaBucket struct {
	ModelID           string     `json:"model_id,omitempty"`
	DisplayName       string     `json:"display_name,omitempty"`
	Type              string     `json:"type"`
	RemainingFraction *float64   `json:"remaining_fraction"`
	ResetTime         *time.Time `json:"reset_time"`
}

var knownThinkingLevelOrder = []struct {
	enum  pb.FetchConfigResponse_ThinkingConfig_ThinkingLevel
	label string
}{
	{pb.FetchConfigResponse_ThinkingConfig_MINIMAL, "minimal"},
	{pb.FetchConfigResponse_ThinkingConfig_LOW, "low"},
	{pb.FetchConfigResponse_ThinkingConfig_MEDIUM, "medium"},
	{pb.FetchConfigResponse_ThinkingConfig_HIGH, "high"},
}

// Models extracts chat_agent_mode models deduplicated by model_id from a successful FetchConfigResponse.
// Returns nil if resp is nil (no unauthorized fallback without a successful FetchConfig call).
// If resp is non-nil but yields no matching chat_agent_mode models, returns the single fallback entry.
func Models(resp *pb.FetchConfigResponse) []Model {
	if resp == nil {
		return nil
	}

	seen := make(map[string]struct{})
	out := make([]Model, 0, len(resp.GetAvailableExperiences()))

	for _, exp := range resp.GetAvailableExperiences() {
		if exp == nil || !strings.HasPrefix(exp.GetName(), ChatAgentExperiencePrefix) {
			continue
		}
		m := exp.GetModel()
		if m == nil {
			continue
		}
		id := m.GetModelId()
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}

		displayName := m.GetDisplayName()
		if displayName == "" {
			displayName = m.GetName()
		}
		if displayName == "" {
			displayName = id
		}

		inLimit := 0
		if v := m.GetInputTokenLimit(); v > 0 {
			inLimit = int(v)
		}
		outLimit := 0
		if v := m.GetOutputTokenLimit(); v > 0 {
			outLimit = int(v)
		}

		supportedLevels := make(map[pb.FetchConfigResponse_ThinkingConfig_ThinkingLevel]struct{}, len(m.GetSupportedThinkingLevels()))
		for _, lvl := range m.GetSupportedThinkingLevels() {
			supportedLevels[lvl] = struct{}{}
		}
		thinkingLevels := make([]string, 0, len(knownThinkingLevelOrder))
		for _, known := range knownThinkingLevelOrder {
			if _, ok := supportedLevels[known.enum]; ok {
				thinkingLevels = append(thinkingLevels, known.label)
			}
		}

		features := make([]string, 0, len(m.GetSupportedFeatures()))
		for _, f := range m.GetSupportedFeatures() {
			if name, ok := pb.FetchConfigResponse_Model_Feature_name[int32(f)]; ok {
				features = append(features, name)
			} else {
				features = append(features, fmt.Sprintf("UNKNOWN_%d", int32(f)))
			}
		}

		out = append(out, Model{
			ID:               id,
			Experience:       exp.GetName(),
			DisplayName:      displayName,
			InputTokenLimit:  inLimit,
			OutputTokenLimit: outLimit,
			ThinkingLevels:   thinkingLevels,
			Features:         features,
			Fallback:         false,
		})
	}

	if len(out) == 0 {
		return []Model{
			{
				ID:             "studio-default",
				Experience:     ChatAgentExperiencePrefix,
				DisplayName:    "Android Studio default",
				ThinkingLevels: []string{},
				Features:       []string{},
				Fallback:       true,
			},
		}
	}
	return out
}

// Quota maps a FetchQuotaStatusResponse into sanitized QuotaBucket entries.
func Quota(resp *pb.FetchQuotaStatusResponse) []QuotaBucket {
	if resp == nil {
		return nil
	}

	out := make([]QuotaBucket, 0, len(resp.GetBuckets()))
	for _, b := range resp.GetBuckets() {
		if b == nil {
			continue
		}

		var modelID, displayName string
		if m := b.GetModel(); m != nil {
			modelID = m.GetModelId()
			displayName = m.GetDisplayName()
		}

		qType, ok := pb.FetchQuotaStatusResponse_QuotaType_name[int32(b.GetQuotaType())]
		if !ok {
			qType = fmt.Sprintf("UNKNOWN_%d", int32(b.GetQuotaType()))
		}

		var remaining *float64
		val := float64(b.GetRemainingFraction())
		if !math.IsNaN(val) && !math.IsInf(val, 0) && val >= 0 && val <= 1 {
			v := val
			remaining = &v
		}

		var resetTime *time.Time
		if ts := b.GetResetTime(); ts != nil && ts.IsValid() {
			t := ts.AsTime().UTC()
			resetTime = &t
		}

		out = append(out, QuotaBucket{
			ModelID:           modelID,
			DisplayName:       displayName,
			Type:              qType,
			RemainingFraction: remaining,
			ResetTime:         resetTime,
		})
	}
	return out
}
