// Package chat translates OpenAI Chat Completions requests and responses
// to and from Google AiCode protobuf messages without performing network I/O
// or tool execution.
package chat

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/aicode"
	pb "github.com/ayatinene/ASGemini2API/internal/aicode/pb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

// PushEmitsInitialRole reports whether Completion.Push emits "role": "assistant"
// on the first streaming delta chunk without a separate Start call.
const PushEmitsInitialRole = true

// Error is an OpenAI-compatible protocol/validation/upstream translation error.
type Error struct {
	Message string
	Code    string
	Param   string
	Status  int
}

func (e *Error) Error() string {
	return e.Message
}

func newInvalidRequestError(message, param string) *Error {
	return &Error{
		Message: message,
		Code:    "invalid_request_error",
		Param:   param,
		Status:  400,
	}
}

func newUnsupportedParamError(message, param string) *Error {
	return &Error{
		Message: message,
		Code:    "unsupported_parameter",
		Param:   param,
		Status:  400,
	}
}

func newUpstreamError(message, code string, status int) *Error {
	return &Error{
		Message: message,
		Code:    code,
		Status:  status,
	}
}

// ExtraContent holds provider-specific OpenAI JSON extensions.
type ExtraContent struct {
	Google *GoogleExtraContent `json:"google,omitempty"`
}

// GoogleExtraContent carries Gemini/AiCode opaque metadata such as thought signatures.
type GoogleExtraContent struct {
	ThoughtSignature string `json:"thought_signature,omitempty"`
}

// ContentPart represents an OpenAI multimodal message content part.
type ContentPart struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}

// ImageURL represents an OpenAI image_url content block payload.
type ImageURL struct {
	URL string `json:"url"`
}

// FunctionCall represents an OpenAI tool function invocation.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolCall represents an OpenAI assistant tool call (streaming or complete).
type ToolCall struct {
	Index        *int          `json:"index,omitempty"`
	ID           string        `json:"id,omitempty"`
	Type         string        `json:"type"`
	Function     FunctionCall  `json:"function"`
	ExtraContent *ExtraContent `json:"extra_content,omitempty"`
}

// Message represents an OpenAI Chat Completions message.
type Message struct {
	Role             string        `json:"role"`
	Content          any           `json:"content"`
	Name             string        `json:"name,omitempty"`
	ReasoningContent string        `json:"reasoning_content,omitempty"`
	ToolCalls        []ToolCall    `json:"tool_calls,omitempty"`
	ToolCallID       string        `json:"tool_call_id,omitempty"`
	ExtraContent     *ExtraContent `json:"extra_content,omitempty"`
}

// StreamOptions configures OpenAI streaming behavior.
type StreamOptions struct {
	IncludeUsage bool `json:"include_usage,omitempty"`
}

// FunctionDefinition defines an OpenAI callable function tool.
type FunctionDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
	Strict      *bool          `json:"strict,omitempty"`
}

// Tool defines an OpenAI tool declaration.
type Tool struct {
	Type     string             `json:"type"`
	Function FunctionDefinition `json:"function"`
}

// JSONSchemaFormat configures structured JSON Schema output.
type JSONSchemaFormat struct {
	Name   string         `json:"name,omitempty"`
	Schema map[string]any `json:"schema,omitempty"`
	Strict *bool          `json:"strict,omitempty"`
}

// ResponseFormat configures OpenAI response formatting.
type ResponseFormat struct {
	Type       string            `json:"type"`
	JSONSchema *JSONSchemaFormat `json:"json_schema,omitempty"`
}

// Request represents an OpenAI Chat Completions request body.
type Request struct {
	Model               string          `json:"model"`
	Messages            []Message       `json:"messages"`
	Stream              bool            `json:"stream,omitempty"`
	StreamOptions       *StreamOptions  `json:"stream_options,omitempty"`
	Tools               []Tool          `json:"tools,omitempty"`
	ToolChoice          any             `json:"tool_choice,omitempty"`
	ReasoningEffort     *string         `json:"reasoning_effort,omitempty"`
	MaxTokens           *int            `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int            `json:"max_completion_tokens,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	TopP                *float64        `json:"top_p,omitempty"`
	Stop                any             `json:"stop,omitempty"`
	N                   *int            `json:"n,omitempty"`
	Seed                *int64          `json:"seed,omitempty"`
	PresencePenalty     *float64        `json:"presence_penalty,omitempty"`
	FrequencyPenalty    *float64        `json:"frequency_penalty,omitempty"`
	ResponseFormat      *ResponseFormat `json:"response_format,omitempty"`
	User                string          `json:"user,omitempty"`

	// Unsupported OpenAI parameters captured so Encode rejects them explicitly
	// instead of silently dropping incompatible semantics.
	Functions         any   `json:"functions,omitempty"`
	FunctionCall      any   `json:"function_call,omitempty"`
	Logprobs          *bool `json:"logprobs,omitempty"`
	TopLogprobs       *int  `json:"top_logprobs,omitempty"`
	LogitBias         any   `json:"logit_bias,omitempty"`
	Audio             any   `json:"audio,omitempty"`
	Modalities        any   `json:"modalities,omitempty"`
	Prediction        any   `json:"prediction,omitempty"`
	ParallelToolCalls *bool `json:"parallel_tool_calls,omitempty"`
}

// PromptTokensDetails reports cached prompt token counts.
type PromptTokensDetails struct {
	CachedTokens int `json:"cached_tokens,omitempty"`
}

// CompletionTokensDetails reports reasoning token counts.
type CompletionTokensDetails struct {
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
}

// Usage reports OpenAI Chat Completions token counts.
type Usage struct {
	PromptTokens            int                      `json:"prompt_tokens"`
	CompletionTokens        int                      `json:"completion_tokens"`
	TotalTokens             int                      `json:"total_tokens"`
	PromptTokensDetails     *PromptTokensDetails     `json:"prompt_tokens_details,omitempty"`
	CompletionTokensDetails *CompletionTokensDetails `json:"completion_tokens_details,omitempty"`
}

// Delta represents incremental fields in a streaming chunk.
type Delta struct {
	Role             string        `json:"role,omitempty"`
	Content          *string       `json:"content,omitempty"`
	ReasoningContent string        `json:"reasoning_content,omitempty"`
	ToolCalls        []ToolCall    `json:"tool_calls,omitempty"`
	ExtraContent     *ExtraContent `json:"extra_content,omitempty"`
}

// ChunkChoice represents one choice in a streaming chunk.
type ChunkChoice struct {
	Index        int     `json:"index"`
	Delta        Delta   `json:"delta"`
	FinishReason *string `json:"finish_reason"`
}

// Chunk represents a single OpenAI chat.completion.chunk SSE payload.
type Chunk struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Created int64         `json:"created"`
	Model   string        `json:"model"`
	Choices []ChunkChoice `json:"choices"`
	Usage   *Usage        `json:"usage"`
}

// Choice represents one choice in a non-streaming completion result.
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// Result represents a non-streaming OpenAI chat.completion response.
type Result struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   *Usage   `json:"usage,omitempty"`
}

// Decode parses an OpenAI Chat Completions JSON request body from r.
// Harmless unknown client fields are ignored, while known incompatible
// parameters are preserved on Request for explicit validation in Encode.
func Decode(r io.Reader) (*Request, error) {
	if r == nil {
		return nil, &Error{Message: "Expected a valid JSON request object.", Code: "invalid_json", Status: 400}
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, &Error{Message: "Failed to read request body.", Code: "invalid_json", Status: 400}
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, &Error{Message: "Expected a valid JSON request object.", Code: "invalid_json", Status: 400}
	}

	var req Request
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	if err := dec.Decode(&req); err != nil {
		var ute *json.UnmarshalTypeError
		if errors.As(err, &ute) && ute.Field != "" {
			topField := strings.Split(ute.Field, ".")[0]
			return nil, newInvalidRequestError(
				fmt.Sprintf("Invalid type for field %q.", topField),
				topField,
			)
		}
		return nil, &Error{Message: "Expected a valid JSON request object.", Code: "invalid_json", Status: 400}
	}

	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, &Error{Message: "Expected a single JSON request object.", Code: "invalid_json", Status: 400}
	}
	return &req, nil
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback deterministic-free entropy via time if crypto/rand ever fails.
		ns := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(ns >> ((i % 8) * 8))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func newChatID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "chatcmpl-" + strings.ReplaceAll(newUUID(), "-", "")[:24]
	}
	return "chatcmpl-" + hex.EncodeToString(b[:])
}

func normalizeFeatures(model aicode.Model) map[string]struct{} {
	if model.Features == nil {
		return nil
	}
	if model.Fallback && len(model.Features) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(model.Features))
	for _, f := range model.Features {
		out[strings.ToUpper(f)] = struct{}{}
	}
	return out
}

func hasFeature(features map[string]struct{}, name string) bool {
	if features == nil {
		return true
	}
	_, ok := features[name]
	return ok
}

func isFinite(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func toJSONValue(v any, param string) (*structpb.Value, error) {
	norm, err := normalizeJSONTree(v, param)
	if err != nil {
		return nil, err
	}
	val, err := structpb.NewValue(norm)
	if err != nil {
		return nil, newInvalidRequestError(fmt.Sprintf("%s contains invalid JSON value: %v", param, err), param)
	}
	return val, nil
}

func toProtoStruct(m map[string]any, param string) (*structpb.Struct, error) {
	norm, err := normalizeJSONTree(m, param)
	if err != nil {
		return nil, err
	}
	mm, ok := norm.(map[string]any)
	if !ok {
		return nil, newInvalidRequestError(fmt.Sprintf("%s must be a JSON object", param), param)
	}
	s, err := structpb.NewStruct(mm)
	if err != nil {
		return nil, newInvalidRequestError(fmt.Sprintf("%s contains invalid struct field: %v", param, err), param)
	}
	return s, nil
}

func normalizeJSONTree(v any, param string) (any, error) {
	switch x := v.(type) {
	case nil, bool, string, int, int32, int64, uint, uint32, uint64:
		return x, nil
	case float32:
		if !isFinite(float64(x)) {
			return nil, newInvalidRequestError(fmt.Sprintf("%s contains non-finite float value", param), param)
		}
		return float64(x), nil
	case float64:
		if !isFinite(x) {
			return nil, newInvalidRequestError(fmt.Sprintf("%s contains non-finite float value", param), param)
		}
		return x, nil
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			n, err := normalizeJSONTree(item, param)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case map[string]string:
		out := make(map[string]any, len(x))
		for k, s := range x {
			out[k] = s
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			n, err := normalizeJSONTree(item, param)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	default:
		return nil, newInvalidRequestError(fmt.Sprintf("%s contains unsupported value type %T", param, v), param)
	}
}

func parseJSONObject(raw string, param, ctx string) (map[string]any, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed[0] != '{' {
		return nil, newInvalidRequestError(fmt.Sprintf("%s must be a JSON object string", ctx), param)
	}
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(trimmed))
	if err := dec.Decode(&obj); err != nil {
		return nil, newInvalidRequestError(fmt.Sprintf("%s must be valid JSON: %v", ctx, err), param)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, newInvalidRequestError(fmt.Sprintf("%s must contain a single JSON object", ctx), param)
	}
	if obj == nil {
		return nil, newInvalidRequestError(fmt.Sprintf("%s must decode to a JSON object", ctx), param)
	}
	return obj, nil
}

func extractThoughtSignature(extra *ExtraContent, param string) ([]byte, error) {
	if extra == nil || extra.Google == nil || extra.Google.ThoughtSignature == "" {
		return nil, nil
	}
	sig, err := base64.StdEncoding.DecodeString(extra.Google.ThoughtSignature)
	if err != nil {
		return nil, newInvalidRequestError("Invalid base64 thought_signature", param)
	}
	return sig, nil
}

func extractTextOnlyContent(content any, allowNil bool, roleLabel string) (string, bool, error) {
	if content == nil {
		if allowNil {
			return "", false, nil
		}
		return "", false, newInvalidRequestError(fmt.Sprintf("%s message content cannot be null", roleLabel), "messages")
	}
	switch v := content.(type) {
	case string:
		return v, true, nil
	case []ContentPart:
		pieces := make([]string, 0, len(v))
		for _, part := range v {
			if part.Type != "text" {
				return "", false, newInvalidRequestError(
					fmt.Sprintf("%s message does not support content part type %q", roleLabel, part.Type),
					"messages",
				)
			}
			pieces = append(pieces, part.Text)
		}
		if len(pieces) > 1 {
			return strings.Join(pieces, "\n"), false, nil
		}
		if len(pieces) == 1 {
			return pieces[0], false, nil
		}
		return "", false, nil
	case []any:
		pieces := make([]string, 0, len(v))
		for _, raw := range v {
			m, ok := raw.(map[string]any)
			if !ok {
				return "", false, newInvalidRequestError(fmt.Sprintf("%s message content part must be an object", roleLabel), "messages")
			}
			ptype, _ := m["type"].(string)
			if ptype != "text" {
				return "", false, newInvalidRequestError(
					fmt.Sprintf("%s message does not support content part type %q", roleLabel, ptype),
					"messages",
				)
			}
			txt, ok := m["text"].(string)
			if !ok {
				return "", false, newInvalidRequestError(fmt.Sprintf("%s text part must include a string 'text'", roleLabel), "messages")
			}
			pieces = append(pieces, txt)
		}
		if len(pieces) > 1 {
			return strings.Join(pieces, "\n"), false, nil
		}
		if len(pieces) == 1 {
			return pieces[0], false, nil
		}
		return "", false, nil
	default:
		return "", false, newInvalidRequestError(fmt.Sprintf("%s message content must be a string or list of parts", roleLabel), "messages")
	}
}

func parseDataURL(url string) (string, []byte, error) {
	if !strings.HasPrefix(url, "data:") {
		return "", nil, newUnsupportedParamError("Only base64 data: URLs are supported for image_url inputs", "messages")
	}
	header, payload, ok := strings.Cut(url[len("data:"):], ",")
	if !ok {
		return "", nil, newInvalidRequestError("Malformed data: URL in image_url", "messages")
	}
	parts := strings.Split(header, ";")
	hasBase64 := false
	mimeType := ""
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "base64" {
			hasBase64 = true
			continue
		}
		if mimeType == "" {
			mimeType = p
		}
	}
	if !hasBase64 {
		return "", nil, newInvalidRequestError("image_url data: URL must be base64-encoded", "messages")
	}
	if mimeType == "" || !strings.Contains(mimeType, "/") {
		return "", nil, newInvalidRequestError("image_url data: URL must specify a valid MIME type", "messages")
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", nil, newInvalidRequestError("Invalid base64 payload in image_url", "messages")
	}
	if len(raw) == 0 {
		return "", nil, newInvalidRequestError("Empty image payload in image_url", "messages")
	}
	return mimeType, raw, nil
}

func parseUserContent(content any, features map[string]struct{}) ([]*pb.Part, error) {
	if content == nil {
		return nil, newInvalidRequestError("User message content cannot be null", "messages")
	}
	switch v := content.(type) {
	case string:
		return []*pb.Part{{Data: &pb.Part_Text{Text: v}}}, nil
	case []ContentPart:
		if len(v) == 0 {
			return nil, newInvalidRequestError("User message content parts list cannot be empty", "messages")
		}
		out := make([]*pb.Part, 0, len(v))
		for _, item := range v {
			switch item.Type {
			case "text":
				out = append(out, &pb.Part{Data: &pb.Part_Text{Text: item.Text}})
			case "image_url":
				if !hasFeature(features, "IMAGE_INPUT") {
					return nil, newUnsupportedParamError("Model does not support image input", "messages")
				}
				if item.ImageURL == nil || item.ImageURL.URL == "" {
					return nil, newInvalidRequestError("image_url.url must be a non-empty string", "messages")
				}
				mime, raw, err := parseDataURL(item.ImageURL.URL)
				if err != nil {
					return nil, err
				}
				out = append(out, &pb.Part{
					Data: &pb.Part_InlineData{
						InlineData: &pb.Blob{MimeType: mime, Data: raw},
					},
				})
			default:
				return nil, newInvalidRequestError(fmt.Sprintf("Unsupported user content part type: %q", item.Type), "messages")
			}
		}
		return out, nil
	case []any:
		if len(v) == 0 {
			return nil, newInvalidRequestError("User message content parts list cannot be empty", "messages")
		}
		out := make([]*pb.Part, 0, len(v))
		for _, raw := range v {
			m, ok := raw.(map[string]any)
			if !ok {
				return nil, newInvalidRequestError("User content part must be an object", "messages")
			}
			ptype, _ := m["type"].(string)
			switch ptype {
			case "text":
				txt, ok := m["text"].(string)
				if !ok {
					return nil, newInvalidRequestError("Text content part must include string 'text'", "messages")
				}
				out = append(out, &pb.Part{Data: &pb.Part_Text{Text: txt}})
			case "image_url":
				if !hasFeature(features, "IMAGE_INPUT") {
					return nil, newUnsupportedParamError("Model does not support image input", "messages")
				}
				var url string
				switch img := m["image_url"].(type) {
				case map[string]any:
					url, _ = img["url"].(string)
				case string:
					url = img
				default:
					return nil, newInvalidRequestError("image_url part must provide an object with 'url'", "messages")
				}
				if url == "" {
					return nil, newInvalidRequestError("image_url.url must be a non-empty string", "messages")
				}
				mime, data, err := parseDataURL(url)
				if err != nil {
					return nil, err
				}
				out = append(out, &pb.Part{
					Data: &pb.Part_InlineData{
						InlineData: &pb.Blob{MimeType: mime, Data: data},
					},
				})
			default:
				return nil, newInvalidRequestError(fmt.Sprintf("Unsupported user content part type: %q", ptype), "messages")
			}
		}
		return out, nil
	default:
		return nil, newInvalidRequestError("User message content must be a string or list of parts", "messages")
	}
}

func parseStopSequences(raw any) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil, newInvalidRequestError("'stop' string cannot be empty", "stop")
		}
		return []string{v}, nil
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if s == "" {
				return nil, newInvalidRequestError("'stop' list must contain non-empty strings", "stop")
			}
			out = append(out, s)
		}
		return out, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok || s == "" {
				return nil, newInvalidRequestError("'stop' list must contain non-empty strings", "stop")
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, newInvalidRequestError("'stop' must be a string or list of strings", "stop")
	}
}

func validateUnsupportedParams(req *Request) error {
	switch {
	case req.Functions != nil:
		return newUnsupportedParamError("Parameter 'functions' is not supported", "functions")
	case req.FunctionCall != nil:
		return newUnsupportedParamError("Parameter 'function_call' is not supported", "function_call")
	case req.LogitBias != nil:
		return newUnsupportedParamError("Parameter 'logit_bias' is not supported", "logit_bias")
	case req.Audio != nil:
		return newUnsupportedParamError("Parameter 'audio' is not supported", "audio")
	case req.Modalities != nil:
		return newUnsupportedParamError("Parameter 'modalities' is not supported", "modalities")
	case req.Prediction != nil:
		return newUnsupportedParamError("Parameter 'prediction' is not supported", "prediction")
	case req.Logprobs != nil && *req.Logprobs:
		return newUnsupportedParamError("Parameter 'logprobs' is not supported", "logprobs")
	case req.TopLogprobs != nil:
		return newUnsupportedParamError("Parameter 'top_logprobs' is not supported", "top_logprobs")
	case req.ParallelToolCalls != nil && !*req.ParallelToolCalls:
		return newUnsupportedParamError("Disabling 'parallel_tool_calls' is not supported", "parallel_tool_calls")
	}
	return nil
}

type pendingCall struct {
	ID   string
	Name string
}

func validateRestoredContent(restored *pb.Content, msg Message) ([]pendingCall, error) {
	if restored.GetRole() != "" && restored.GetRole() != "model" {
		return nil, newInvalidRequestError("Restored assistant Content has invalid role", "messages")
	}
	if len(restored.GetParts()) == 0 {
		return nil, newInvalidRequestError("Restored assistant Content has no parts", "messages")
	}
	var calls []pendingCall
	seen := make(map[string]struct{})
	for _, part := range restored.GetParts() {
		if part == nil {
			return nil, newInvalidRequestError("Restored assistant Content has an empty part", "messages")
		}
		if fc, ok := part.GetData().(*pb.Part_FunctionCall); ok {
			if fc == nil || fc.FunctionCall.GetId() == "" || fc.FunctionCall.GetName() == "" {
				return nil, newInvalidRequestError("Restored assistant Content has an invalid function call", "messages")
			}
			id := fc.FunctionCall.GetId()
			if _, duplicate := seen[id]; duplicate {
				return nil, newInvalidRequestError("Restored assistant Content has a duplicate function call ID", "messages")
			}
			seen[id] = struct{}{}
			calls = append(calls, pendingCall{ID: id, Name: fc.FunctionCall.GetName()})
		}
	}
	if len(msg.ToolCalls) == 0 {
		if len(calls) > 0 {
			return nil, newInvalidRequestError("Assistant message omits tool_calls present in restored history", "messages")
		}
		return nil, nil
	}
	if len(msg.ToolCalls) != len(calls) {
		return nil, newInvalidRequestError("Assistant tool_calls count does not match restored history", "messages")
	}
	for i, tc := range msg.ToolCalls {
		if tc.Type != "function" || tc.ID != calls[i].ID || tc.Function.Name != calls[i].Name {
			return nil, newInvalidRequestError("Assistant tool_calls do not match restored history", "messages")
		}
	}
	return calls, nil
}

// Encode translates a decoded OpenAI Request into a protobuf GenerateContentRequest.
func Encode(
	req *Request,
	model aicode.Model,
	sessionID string,
	restore func(index int, msg Message) *pb.Content,
) (*pb.GenerateContentRequest, error) {
	if req == nil {
		return nil, newInvalidRequestError("Request body is required", "")
	}
	if model.ID == "" {
		return nil, &Error{Message: "Resolved model must have a non-empty 'id'", Code: "invalid_model", Param: "model", Status: 400}
	}
	if model.Experience == "" {
		return nil, &Error{Message: "Resolved model must have a non-empty 'experience'", Code: "invalid_model", Param: "model", Status: 400}
	}
	if err := validateUnsupportedParams(req); err != nil {
		return nil, err
	}

	features := normalizeFeatures(model)
	genCfg := &pb.GenerationConfig{
		CandidateCount: proto.Int32(1),
	}
	out := &pb.GenerateContentRequest{
		Inference: &pb.GenerateContentRequest_Aicode{
			Aicode: &pb.AiCodeConfig{
				Experience: model.Experience,
			},
		},
		GenerationConfig: genCfg,
		SessionId:        sessionID,
	}

	if req.N != nil && *req.N != 1 {
		return nil, newUnsupportedParamError("Only n=1 is supported", "n")
	}

	if req.MaxTokens != nil && *req.MaxTokens <= 0 {
		return nil, newInvalidRequestError("'max_tokens' must be a positive integer", "max_tokens")
	}
	if req.MaxCompletionTokens != nil && *req.MaxCompletionTokens <= 0 {
		return nil, newInvalidRequestError("'max_completion_tokens' must be a positive integer", "max_completion_tokens")
	}
	if req.MaxTokens != nil && req.MaxCompletionTokens != nil && *req.MaxTokens != *req.MaxCompletionTokens {
		return nil, newInvalidRequestError("Conflicting 'max_tokens' and 'max_completion_tokens' values", "max_completion_tokens")
	}
	var effectiveMax int
	var maxParam string
	if req.MaxCompletionTokens != nil {
		effectiveMax = *req.MaxCompletionTokens
		maxParam = "max_completion_tokens"
	} else if req.MaxTokens != nil {
		effectiveMax = *req.MaxTokens
		maxParam = "max_tokens"
	}
	if maxParam != "" {
		if effectiveMax > math.MaxInt32 {
			return nil, newInvalidRequestError(fmt.Sprintf("'%s' exceeds int32 range", maxParam), maxParam)
		}
		if model.OutputTokenLimit > 0 && effectiveMax > model.OutputTokenLimit {
			return nil, newInvalidRequestError(
				fmt.Sprintf("Requested %s (%d) exceeds model output_token_limit (%d)", maxParam, effectiveMax, model.OutputTokenLimit),
				maxParam,
			)
		}
		genCfg.MaxOutputTokens = proto.Int32(int32(effectiveMax))
	}

	if req.Temperature != nil {
		t := *req.Temperature
		if !isFinite(t) || t < 0.0 || t > 2.0 {
			return nil, newInvalidRequestError("'temperature' must be a finite number between 0 and 2", "temperature")
		}
		genCfg.Temperature = proto.Float32(float32(t))
	}

	if req.TopP != nil {
		p := *req.TopP
		if !isFinite(p) || p < 0.0 || p > 1.0 {
			return nil, newInvalidRequestError("'top_p' must be a finite number between 0 and 1", "top_p")
		}
		if !hasFeature(features, "TOP_P") {
			return nil, newUnsupportedParamError(fmt.Sprintf("Model %q does not support 'top_p'", model.ID), "top_p")
		}
		genCfg.TopP = proto.Float32(float32(p))
	}

	stops, err := parseStopSequences(req.Stop)
	if err != nil {
		return nil, err
	}
	if len(stops) > 0 {
		genCfg.StopSequences = stops
	}

	if req.Seed != nil {
		s := *req.Seed
		if s < math.MinInt32 || s > math.MaxInt32 {
			return nil, newInvalidRequestError("'seed' must be a 32-bit signed integer", "seed")
		}
		genCfg.Seed = proto.Int32(int32(s))
	}

	if req.PresencePenalty != nil {
		v := *req.PresencePenalty
		if !isFinite(v) || v < -2.0 || v > 2.0 {
			return nil, newInvalidRequestError("'presence_penalty' must be between -2 and 2", "presence_penalty")
		}
		genCfg.PresencePenalty = proto.Float32(float32(v))
	}
	if req.FrequencyPenalty != nil {
		v := *req.FrequencyPenalty
		if !isFinite(v) || v < -2.0 || v > 2.0 {
			return nil, newInvalidRequestError("'frequency_penalty' must be between -2 and 2", "frequency_penalty")
		}
		genCfg.FrequencyPenalty = proto.Float32(float32(v))
	}

	if req.ResponseFormat != nil {
		if req.ResponseFormat.JSONSchema != nil && req.ResponseFormat.JSONSchema.Strict != nil && *req.ResponseFormat.JSONSchema.Strict {
			return nil, newUnsupportedParamError("Strict JSON schema mode (strict=true) is not supported", "response_format")
		}
		switch req.ResponseFormat.Type {
		case "text":
		case "json_object":
			genCfg.ResponseMimeType = proto.String("application/json")
		case "json_schema":
			if !hasFeature(features, "JSON_SCHEMA_OUTPUT") {
				return nil, newUnsupportedParamError(fmt.Sprintf("Model %q does not support json_schema output", model.ID), "response_format")
			}
			if req.ResponseFormat.JSONSchema == nil || req.ResponseFormat.JSONSchema.Schema == nil {
				return nil, newInvalidRequestError("response_format.json_schema.schema must be an object", "response_format")
			}
			val, err := toJSONValue(req.ResponseFormat.JSONSchema.Schema, "response_format")
			if err != nil {
				return nil, err
			}
			genCfg.ResponseMimeType = proto.String("application/json")
			genCfg.ResponseJsonSchema = val
		default:
			return nil, newUnsupportedParamError(
				fmt.Sprintf("Unsupported response_format.type: %q", req.ResponseFormat.Type),
				"response_format",
			)
		}
	}

	if req.ReasoningEffort != nil {
		rawEffort := *req.ReasoningEffort
		effort := strings.ToLower(strings.TrimSpace(rawEffort))
		if effort == "" {
			return nil, newInvalidRequestError("'reasoning_effort' must be a non-empty string", "reasoning_effort")
		}
		// The IDE derives the set of permitted levels from the experience's
		// supported_thinking_levels, not from a separate feature bit.
		supported := false
		for _, lvl := range model.ThinkingLevels {
			if strings.ToLower(lvl) == effort {
				supported = true
				break
			}
		}
		if !supported {
			return nil, newUnsupportedParamError(
				fmt.Sprintf("Unsupported reasoning_effort %q for model %q", rawEffort, model.ID),
				"reasoning_effort",
			)
		}
		ev := pb.GenerationConfig_ThinkingConfig_ThinkingLevel(0).Descriptor().Values().ByName(protoreflect.Name(strings.ToUpper(effort)))
		if ev == nil || ev.Number() == 0 {
			return nil, newUnsupportedParamError(
				fmt.Sprintf("Unsupported reasoning_effort %q in wire ThinkingLevel enum", rawEffort),
				"reasoning_effort",
			)
		}
		tl := pb.GenerationConfig_ThinkingConfig_ThinkingLevel(ev.Number())
		genCfg.ThinkingConfig = &pb.GenerationConfig_ThinkingConfig{
			IncludeThoughts: proto.Bool(true),
			ThinkingLevel:   &tl,
		}
	}

	// Tools & tool_choice
	declaredTools := make(map[string]struct{}, len(req.Tools))
	if len(req.Tools) > 0 {
		if !hasFeature(features, "FUNCTION_CALLING") {
			return nil, newUnsupportedParamError(fmt.Sprintf("Model %q does not support function calling", model.ID), "tools")
		}
		decls := make([]*pb.FunctionDeclaration, 0, len(req.Tools))
		for _, entry := range req.Tools {
			if entry.Type != "function" {
				return nil, newUnsupportedParamError(fmt.Sprintf("Unsupported tool type: %q", entry.Type), "tools")
			}
			if entry.Function.Strict != nil && *entry.Function.Strict {
				return nil, newUnsupportedParamError("Strict function calling mode (strict=true) is not supported", "tools")
			}
			if entry.Function.Name == "" {
				return nil, newInvalidRequestError("Tool function must include a non-empty string 'name'", "tools")
			}
			if _, dup := declaredTools[entry.Function.Name]; dup {
				return nil, newInvalidRequestError(fmt.Sprintf("Duplicate tool function name: %q", entry.Function.Name), "tools")
			}
			declaredTools[entry.Function.Name] = struct{}{}

			fd := &pb.FunctionDeclaration{
				Name:        entry.Function.Name,
				Description: entry.Function.Description,
			}
			if entry.Function.Parameters != nil {
				val, err := toJSONValue(entry.Function.Parameters, "tools")
				if err != nil {
					return nil, err
				}
				fd.ParametersJsonSchema = val
			}
			decls = append(decls, fd)
		}
		out.Tools = []*pb.Tool{{FunctionDeclarations: decls}}
	}

	if req.ToolChoice != nil {
		if out.ProtoReflect().Descriptor().Fields().ByName("tool_config") == nil {
			return nil, newUnsupportedParamError("'tool_choice' is not supported by wire schema", "tool_choice")
		}
		switch tc := req.ToolChoice.(type) {
		case string:
			switch tc {
			case "auto":
				if len(declaredTools) > 0 {
					out.ToolConfig = &pb.ToolConfig{
						FunctionCallingConfig: &pb.FunctionCallingConfig{
							Mode: pb.FunctionCallingConfig_AUTO,
						},
					}
				}
			case "none":
				out.ToolConfig = &pb.ToolConfig{
					FunctionCallingConfig: &pb.FunctionCallingConfig{
						Mode: pb.FunctionCallingConfig_NONE,
					},
				}
			case "required":
				if len(declaredTools) == 0 {
					return nil, newInvalidRequestError("tool_choice='required' requires non-empty 'tools'", "tool_choice")
				}
				out.ToolConfig = &pb.ToolConfig{
					FunctionCallingConfig: &pb.FunctionCallingConfig{
						Mode: pb.FunctionCallingConfig_ANY,
					},
				}
			default:
				return nil, newUnsupportedParamError(fmt.Sprintf("Unsupported tool_choice: %q", tc), "tool_choice")
			}
		case map[string]any:
			tcType, _ := tc["type"].(string)
			if tcType != "function" {
				return nil, newUnsupportedParamError(fmt.Sprintf("Unsupported tool_choice.type: %q", tcType), "tool_choice")
			}
			fnObj, ok := tc["function"].(map[string]any)
			if !ok {
				return nil, newInvalidRequestError("tool_choice.function must be an object", "tool_choice")
			}
			fnName, _ := fnObj["name"].(string)
			if fnName == "" {
				return nil, newInvalidRequestError("tool_choice.function.name must be a non-empty string", "tool_choice")
			}
			if _, ok := declaredTools[fnName]; !ok {
				return nil, newInvalidRequestError(fmt.Sprintf("tool_choice references undeclared tool %q", fnName), "tool_choice")
			}
			out.ToolConfig = &pb.ToolConfig{
				FunctionCallingConfig: &pb.FunctionCallingConfig{
					Mode:                 pb.FunctionCallingConfig_ANY,
					AllowedFunctionNames: []string{fnName},
				},
			}
		default:
			return nil, newInvalidRequestError("'tool_choice' must be a string or object", "tool_choice")
		}
	}

	// Messages translation
	if len(req.Messages) == 0 {
		return nil, newInvalidRequestError("'messages' must be a non-empty list", "messages")
	}

	var systemTexts []string
	var contents []*pb.Content
	var pending []pendingCall
	collected := make(map[string]string)

	flushPendingTools := func() error {
		if len(pending) == 0 {
			return nil
		}
		frParts := make([]*pb.Part, 0, len(pending))
		for _, pc := range pending {
			res, ok := collected[pc.ID]
			if !ok {
				return newInvalidRequestError(fmt.Sprintf("Missing tool response for tool_call_id %q", pc.ID), "messages")
			}
			respStruct, err := toProtoStruct(map[string]any{"result": res}, "messages")
			if err != nil {
				return err
			}
			frParts = append(frParts, &pb.Part{
				Data: &pb.Part_FunctionResponse{
					FunctionResponse: &pb.FunctionResponse{
						Id:       pc.ID,
						Name:     pc.Name,
						Response: respStruct,
					},
				},
			})
		}
		if len(contents) > 0 && contents[len(contents)-1].GetRole() == "user" {
			contents[len(contents)-1].Parts = append(contents[len(contents)-1].Parts, frParts...)
		} else {
			contents = append(contents, &pb.Content{Role: "user", Parts: frParts})
		}
		pending = nil
		clear(collected)
		return nil
	}

	for idx, msg := range req.Messages {
		switch msg.Role {
		case "system", "developer":
			if len(pending) > 0 {
				return nil, newInvalidRequestError("Assistant tool_calls must be followed by matching tool responses", "messages")
			}
			if len(msg.ToolCalls) > 0 || msg.ToolCallID != "" {
				return nil, newInvalidRequestError(fmt.Sprintf("%s message cannot contain tool_calls or tool_call_id", msg.Role), "messages")
			}
			txt, _, err := extractTextOnlyContent(msg.Content, false, msg.Role)
			if err != nil {
				return nil, err
			}
			if txt != "" {
				systemTexts = append(systemTexts, txt)
			}

		case "user":
			if err := flushPendingTools(); err != nil {
				return nil, err
			}
			if len(msg.ToolCalls) > 0 || msg.ToolCallID != "" {
				return nil, newInvalidRequestError("User message cannot contain tool_calls or tool_call_id", "messages")
			}
			parts, err := parseUserContent(msg.Content, features)
			if err != nil {
				return nil, err
			}
			if len(contents) > 0 && contents[len(contents)-1].GetRole() == "user" {
				contents[len(contents)-1].Parts = append(contents[len(contents)-1].Parts, parts...)
			} else {
				contents = append(contents, &pb.Content{Role: "user", Parts: parts})
			}

		case "assistant":
			if err := flushPendingTools(); err != nil {
				return nil, err
			}
			if msg.ToolCallID != "" {
				return nil, newInvalidRequestError("Assistant message cannot contain tool_call_id", "messages")
			}

			if restore != nil {
				if restored := restore(idx, msg); restored != nil {
					calls, err := validateRestoredContent(restored, msg)
					if err != nil {
						return nil, err
					}
					cloned := proto.Clone(restored).(*pb.Content)
					cloned.Role = "model"
					contents = append(contents, cloned)
					if len(calls) > 0 {
						pending = calls
						clear(collected)
					}
					continue
				}
			}

			// Fallback encoding
			textContent, hasContentStr, err := extractTextOnlyContent(msg.Content, true, "assistant")
			if err != nil {
				return nil, err
			}
			msgSig, err := extractThoughtSignature(msg.ExtraContent, "messages")
			if err != nil {
				return nil, err
			}

			type parsedCall struct {
				id   string
				name string
				args map[string]any
				sig  []byte
			}
			parsedCalls := make([]parsedCall, 0, len(msg.ToolCalls))
			seenIDs := make(map[string]struct{}, len(msg.ToolCalls))
			for _, tc := range msg.ToolCalls {
				if tc.Type != "function" {
					return nil, newInvalidRequestError(fmt.Sprintf("Unsupported tool_call type: %q", tc.Type), "messages")
				}
				if tc.ID == "" {
					return nil, newInvalidRequestError("tool_call 'id' must be a non-empty string", "messages")
				}
				if _, dup := seenIDs[tc.ID]; dup {
					return nil, newInvalidRequestError(fmt.Sprintf("Duplicate tool_call id %q in assistant message", tc.ID), "messages")
				}
				seenIDs[tc.ID] = struct{}{}
				if tc.Function.Name == "" {
					return nil, newInvalidRequestError("tool_call function.name must be a non-empty string", "messages")
				}
				argsObj, err := parseJSONObject(
					tc.Function.Arguments,
					"messages",
					fmt.Sprintf("tool_call %q function.arguments", tc.Function.Name),
				)
				if err != nil {
					return nil, err
				}
				tcSig, err := extractThoughtSignature(tc.ExtraContent, "messages")
				if err != nil {
					return nil, err
				}
				parsedCalls = append(parsedCalls, parsedCall{
					id:   tc.ID,
					name: tc.Function.Name,
					args: argsObj,
					sig:  tcSig,
				})
			}

			if len(parsedCalls) == 0 && (msg.Content == nil || (textContent == "" && !hasContentStr)) && msg.ReasoningContent == "" && len(msgSig) == 0 {
				return nil, newInvalidRequestError("Assistant message must contain content or tool_calls", "messages")
			}

			var parts []*pb.Part
			msgSigUsed := false
			hasVisibleText := textContent != "" || (hasContentStr && len(parsedCalls) == 0 && msg.ReasoningContent == "")

			if msg.ReasoningContent != "" && !hasVisibleText && len(msgSig) > 0 && len(parsedCalls) == 0 {
				parts = append(parts, &pb.Part{
					Thought:          true,
					ThoughtSignature: slices.Clone(msgSig),
					Data:             &pb.Part_Text{Text: msg.ReasoningContent},
				})
				msgSigUsed = true
			}

			if hasVisibleText {
				p := &pb.Part{Data: &pb.Part_Text{Text: textContent}}
				if len(msgSig) > 0 && !msgSigUsed {
					p.ThoughtSignature = slices.Clone(msgSig)
					msgSigUsed = true
				}
				parts = append(parts, p)
			}

			for i, call := range parsedCalls {
				argsStruct, err := toProtoStruct(call.args, "messages")
				if err != nil {
					return nil, err
				}
				sig := call.sig
				if len(sig) == 0 && i == 0 && len(msgSig) > 0 && !msgSigUsed && !hasVisibleText {
					sig = msgSig
					msgSigUsed = true
				}
				p := &pb.Part{
					Data: &pb.Part_FunctionCall{
						FunctionCall: &pb.FunctionCall{
							Id:   call.id,
							Name: call.name,
							Args: argsStruct,
						},
					},
				}
				if len(sig) > 0 {
					p.ThoughtSignature = slices.Clone(sig)
				}
				parts = append(parts, p)
			}

			if len(msgSig) > 0 && !msgSigUsed && len(parts) == 0 {
				parts = append(parts, &pb.Part{
					ThoughtSignature: slices.Clone(msgSig),
					Data:             &pb.Part_Text{Text: ""},
				})
			}

			contents = append(contents, &pb.Content{Role: "model", Parts: parts})
			if len(parsedCalls) > 0 {
				pending = make([]pendingCall, len(parsedCalls))
				for i, c := range parsedCalls {
					pending[i] = pendingCall{ID: c.id, Name: c.name}
				}
				clear(collected)
			}

		case "tool":
			if len(pending) == 0 {
				return nil, newInvalidRequestError("Tool message must follow an assistant message with tool_calls", "messages")
			}
			if msg.ToolCallID == "" {
				return nil, newInvalidRequestError("Tool message must include non-empty 'tool_call_id'", "messages")
			}
			matchedName := ""
			found := false
			for _, pc := range pending {
				if pc.ID == msg.ToolCallID {
					matchedName = pc.Name
					found = true
					break
				}
			}
			if !found {
				return nil, newInvalidRequestError(fmt.Sprintf("Tool message references unknown tool_call_id %q", msg.ToolCallID), "messages")
			}
			if _, dup := collected[msg.ToolCallID]; dup {
				return nil, newInvalidRequestError(fmt.Sprintf("Duplicate tool response for tool_call_id %q", msg.ToolCallID), "messages")
			}
			if msg.Name != "" && msg.Name != matchedName {
				return nil, newInvalidRequestError(
					fmt.Sprintf("Tool message 'name' (%q) does not match call (%q)", msg.Name, matchedName),
					"messages",
				)
			}
			resultStr, _, err := extractTextOnlyContent(msg.Content, false, "tool")
			if err != nil {
				return nil, err
			}
			collected[msg.ToolCallID] = resultStr

		default:
			return nil, newInvalidRequestError(fmt.Sprintf("Unsupported message role: %q", msg.Role), "messages")
		}
	}

	if err := flushPendingTools(); err != nil {
		return nil, err
	}
	if len(contents) == 0 {
		return nil, newInvalidRequestError("'messages' must contain at least one non-system conversation message", "messages")
	}

	if len(systemTexts) > 0 {
		out.SystemInstruction = &pb.Content{
			Role: "user",
			Parts: []*pb.Part{
				{Data: &pb.Part_Text{Text: strings.Join(systemTexts, "\n\n")}},
			},
		}
	}
	out.Contents = contents
	return out, nil
}

// Completion accumulates streamed GenerateContentResponse frames into OpenAI
// streaming chunks, non-streaming Result, and clean-finish history Content.
type Completion struct {
	id           string
	created      int64
	modelID      string
	includeUsage bool

	roleEmitted        bool
	finished           bool
	rawFinishReason    string
	finishReason       string
	textParts          []string
	hasText            bool
	reasoningParts     []string
	toolCalls          []ToolCall
	toolIDs            map[string]struct{}
	textThoughtSig     string
	fallbackThoughtSig string
	upstreamContent    *pb.Content

	sawUsage         bool
	promptTokens     int
	candidatesTokens int
	thoughtsTokens   int
	totalTokens      int
	hasTotalTokens   bool
	cachedTokens     int
}

// NewCompletion initializes a Completion accumulator with pinned id and created timestamp.
func NewCompletion(model string, includeUsage bool) *Completion {
	return &Completion{
		id:              newChatID(),
		created:         time.Now().Unix(),
		modelID:         model,
		includeUsage:    includeUsage,
		upstreamContent: &pb.Content{Role: "model"},
	}
}

func (c *Completion) makeChunk(choices []ChunkChoice, usage *Usage) Chunk {
	return Chunk{
		ID:      c.id,
		Object:  "chat.completion.chunk",
		Created: c.created,
		Model:   c.modelID,
		Choices: choices,
		Usage:   usage,
	}
}

func (c *Completion) emitDelta(delta Delta) Chunk {
	if !c.roleEmitted {
		c.roleEmitted = true
		delta.Role = "assistant"
	}
	return c.makeChunk([]ChunkChoice{
		{
			Index:        0,
			Delta:        delta,
			FinishReason: nil,
		},
	}, nil)
}

func (c *Completion) updateUsage(resp *pb.GenerateContentResponse) {
	um := resp.GetUsageMetadata()
	if um == nil {
		return
	}
	c.sawUsage = true
	if um.GetPromptTokenCount() != 0 {
		c.promptTokens = int(um.GetPromptTokenCount())
	}
	if um.GetCandidatesTokenCount() != 0 {
		c.candidatesTokens = int(um.GetCandidatesTokenCount())
	}
	if um.GetThoughtsTokenCount() != 0 {
		c.thoughtsTokens = int(um.GetThoughtsTokenCount())
	}
	if um.GetTotalTokenCount() != 0 {
		c.totalTokens = int(um.GetTotalTokenCount())
		c.hasTotalTokens = true
	}
	if um.GetCachedContentTokenCount() != 0 {
		c.cachedTokens = int(um.GetCachedContentTokenCount())
	}
}

func (c *Completion) buildUsage() *Usage {
	if !c.sawUsage {
		return nil
	}
	completion := c.candidatesTokens + c.thoughtsTokens
	total := c.promptTokens + completion
	if c.hasTotalTokens {
		total = c.totalTokens
	}
	u := &Usage{
		PromptTokens:     c.promptTokens,
		CompletionTokens: completion,
		TotalTokens:      total,
	}
	if c.thoughtsTokens > 0 {
		u.CompletionTokensDetails = &CompletionTokensDetails{ReasoningTokens: c.thoughtsTokens}
	}
	if c.cachedTokens > 0 {
		u.PromptTokensDetails = &PromptTokensDetails{CachedTokens: c.cachedTokens}
	}
	return u
}

func (c *Completion) resolveFinishReason(cand *pb.Candidate) (string, error) {
	raw := cand.GetFinishReason()
	if raw == 0 {
		return "", nil
	}
	ev := raw.Descriptor().Values().ByNumber(protoreflect.EnumNumber(raw))
	if ev == nil {
		return "", newUpstreamError(fmt.Sprintf("Unknown upstream finish_reason enum number %d", raw), "upstream_error", 502)
	}
	name := string(ev.Name())
	c.rawFinishReason = name
	switch name {
	case "FINISH_REASON_UNSPECIFIED":
		return "", nil
	case "STOP":
		if len(c.toolCalls) > 0 {
			return "tool_calls", nil
		}
		return "stop", nil
	case "MAX_TOKENS":
		return "length", nil
	case "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII",
		"IMAGE_SAFETY", "IMAGE_PROHIBITED_CONTENT", "IMAGE_RECITATION":
		return "content_filter", nil
	case "MALFORMED_FUNCTION_CALL", "UNEXPECTED_TOOL_CALL", "NO_IMAGE":
		return "", newUpstreamError(fmt.Sprintf("Upstream generation failed with finish_reason=%s", name), "upstream_error", 502)
	case "OTHER", "IMAGE_OTHER":
		if len(c.toolCalls) > 0 {
			return "tool_calls", nil
		}
		if c.hasText || len(c.reasoningParts) > 0 {
			return "stop", nil
		}
		return "", newUpstreamError(fmt.Sprintf("Upstream generation ended empty with finish_reason=%s", name), "upstream_error", 502)
	default:
		return "", newUpstreamError(fmt.Sprintf("Unsupported upstream finish_reason=%s", name), "upstream_error", 502)
	}
}

// Push processes one upstream GenerateContentResponse and returns incremental OpenAI streaming chunks.
func (c *Completion) Push(resp *pb.GenerateContentResponse) ([]Chunk, error) {
	if c.finished {
		return nil, &Error{Message: "Cannot push response after completion finished", Code: "invalid_state", Status: 500}
	}
	if c.modelID == "" {
		return nil, &Error{Message: "model must be a non-empty string", Code: "invalid_model", Param: "model", Status: 400}
	}
	if resp == nil {
		return nil, newUpstreamError("Invalid upstream message: nil GenerateContentResponse", "upstream_error", 502)
	}

	c.updateUsage(resp)

	if pf := resp.GetPromptFeedback(); pf != nil && pf.GetBlockReason() != 0 {
		br := pf.GetBlockReason()
		brName := br.String()
		if ev := br.Descriptor().Values().ByNumber(protoreflect.EnumNumber(br)); ev != nil {
			brName = string(ev.Name())
		}
		return nil, newUpstreamError(fmt.Sprintf("Prompt blocked by upstream (%s)", brName), "content_filter", 400)
	}

	cands := resp.GetCandidates()
	if len(cands) == 0 {
		return nil, nil
	}
	cand := cands[0]
	if cand.GetAicodeOutput() != nil && cand.GetContent() == nil {
		return nil, newUpstreamError("Unsupported upstream aicode_output without content", "upstream_error", 502)
	}

	var chunks []Chunk
	if content := cand.GetContent(); content != nil {
		if role := content.GetRole(); role != "" && role != "model" {
			return nil, newUpstreamError("Unexpected upstream candidate content role", "upstream_error", 502)
		}

		for _, part := range content.GetParts() {
			if part == nil {
				return nil, newUpstreamError("Upstream returned an empty candidate part", "upstream_error", 502)
			}
			stored := proto.Clone(part).(*pb.Part)
			c.upstreamContent.Parts = append(c.upstreamContent.Parts, stored)

			var sigB64 string
			if sig := part.GetThoughtSignature(); len(sig) > 0 {
				sigB64 = base64.StdEncoding.EncodeToString(sig)
			}

			switch d := part.GetData().(type) {
			case *pb.Part_Text:
				if d == nil {
					return nil, newUpstreamError("Upstream returned an empty text part", "upstream_error", 502)
				}
				if part.GetThought() {
					if d.Text != "" {
						c.reasoningParts = append(c.reasoningParts, d.Text)
						chunks = append(chunks, c.emitDelta(Delta{ReasoningContent: d.Text}))
					}
					if sigB64 != "" {
						c.fallbackThoughtSig = sigB64
					}
				} else {
					c.hasText = true
					if d.Text != "" {
						c.textParts = append(c.textParts, d.Text)
					}
					if sigB64 != "" {
						c.textThoughtSig = sigB64
					}
					if d.Text != "" || sigB64 != "" {
						txt := d.Text
						delta := Delta{Content: &txt}
						if sigB64 != "" {
							delta.ExtraContent = &ExtraContent{Google: &GoogleExtraContent{ThoughtSignature: sigB64}}
						}
						chunks = append(chunks, c.emitDelta(delta))
					}
				}

			case *pb.Part_FunctionCall:
				if d == nil {
					return nil, newUpstreamError("Upstream returned an empty function call", "upstream_error", 502)
				}
				fc := d.FunctionCall
				if fc == nil || fc.GetName() == "" {
					return nil, newUpstreamError("Upstream function_call missing function name", "upstream_error", 502)
				}
				callID := fc.GetId()
				if callID == "" {
					callID = newUUID()
					stored.GetFunctionCall().Id = callID
				}
				if c.toolIDs == nil {
					c.toolIDs = make(map[string]struct{})
				}
				if _, duplicate := c.toolIDs[callID]; duplicate {
					return nil, newUpstreamError("Upstream returned a duplicate function call ID", "upstream_error", 502)
				}
				c.toolIDs[callID] = struct{}{}
				argsMap := map[string]any{}
				if fc.GetArgs() != nil {
					argsMap = fc.GetArgs().AsMap()
				}
				argsBytes, err := json.Marshal(argsMap)
				if err != nil {
					return nil, newUpstreamError(fmt.Sprintf("Failed to marshal upstream function_call args: %v", err), "upstream_error", 502)
				}

				idx := len(c.toolCalls)
				tc := ToolCall{
					ID:   callID,
					Type: "function",
					Function: FunctionCall{
						Name:      fc.GetName(),
						Arguments: string(argsBytes),
					},
				}
				if sigB64 != "" {
					tc.ExtraContent = &ExtraContent{Google: &GoogleExtraContent{ThoughtSignature: sigB64}}
				}
				c.toolCalls = append(c.toolCalls, tc)

				deltaTC := tc
				deltaTC.Index = &idx
				if tc.ExtraContent != nil {
					ecCopy := *tc.ExtraContent
					if ecCopy.Google != nil {
						gCopy := *ecCopy.Google
						ecCopy.Google = &gCopy
					}
					deltaTC.ExtraContent = &ecCopy
				}
				chunks = append(chunks, c.emitDelta(Delta{ToolCalls: []ToolCall{deltaTC}}))

			case nil:
				if sigB64 != "" {
					c.fallbackThoughtSig = sigB64
				} else {
					return nil, newUpstreamError("Unsupported or empty upstream Part data case", "upstream_error", 502)
				}

			default:
				return nil, newUpstreamError(fmt.Sprintf("Unsupported upstream Part data type %T", d), "upstream_error", 502)
			}
		}
	}

	fr, err := c.resolveFinishReason(cand)
	if err != nil {
		return nil, err
	}
	if fr != "" {
		c.finishReason = fr
	}
	return chunks, nil
}

func (c *Completion) validateCompleted() error {
	if c.modelID == "" {
		return &Error{Message: "model must be a non-empty string", Code: "invalid_model", Param: "model", Status: 400}
	}
	if c.finishReason == "" {
		return newUpstreamError("Upstream stream ended without a semantic finish_reason", "incomplete_response", 502)
	}
	if c.rawFinishReason == "STOP" && len(c.upstreamContent.GetParts()) == 0 {
		return newUpstreamError("Upstream returned STOP with no response content parts", "upstream_error", 502)
	}
	if c.rawFinishReason == "STOP" && len(c.toolCalls) > 0 {
		c.finishReason = "tool_calls"
	}
	return nil
}

func cloneToolCalls(in []ToolCall) []ToolCall {
	if len(in) == 0 {
		return nil
	}
	out := make([]ToolCall, len(in))
	for i, tc := range in {
		out[i] = tc
		if tc.ExtraContent != nil {
			ec := *tc.ExtraContent
			if ec.Google != nil {
				g := *ec.Google
				ec.Google = &g
			}
			out[i].ExtraContent = &ec
		}
	}
	return out
}

func (c *Completion) buildAssistantMessage() Message {
	var content any
	if c.hasText {
		content = strings.Join(c.textParts, "")
	} else if len(c.toolCalls) > 0 {
		content = nil
	} else {
		content = ""
	}

	msg := Message{
		Role:      "assistant",
		Content:   content,
		ToolCalls: cloneToolCalls(c.toolCalls),
	}
	if len(c.reasoningParts) > 0 {
		msg.ReasoningContent = strings.Join(c.reasoningParts, "")
	}
	sig := c.textThoughtSig
	if sig == "" && c.fallbackThoughtSig != "" && len(c.toolCalls) == 0 {
		sig = c.fallbackThoughtSig
	}
	if sig != "" {
		msg.ExtraContent = &ExtraContent{Google: &GoogleExtraContent{ThoughtSignature: sig}}
	}
	return msg
}

// Finish validates semantic completion and emits terminal finish_reason (and optional usage) chunks.
func (c *Completion) Finish() ([]Chunk, error) {
	if c.finished {
		return nil, nil
	}
	if err := c.validateCompleted(); err != nil {
		return nil, err
	}
	c.finished = true

	var out []Chunk
	if !c.roleEmitted {
		empty := ""
		out = append(out, c.emitDelta(Delta{Content: &empty}))
	}
	fr := c.finishReason
	out = append(out, c.makeChunk([]ChunkChoice{
		{
			Index:        0,
			Delta:        Delta{},
			FinishReason: &fr,
		},
	}, nil))
	if c.includeUsage {
		if usage := c.buildUsage(); usage != nil {
			out = append(out, c.makeChunk([]ChunkChoice{}, usage))
		}
	}
	return out, nil
}

// Result validates semantic completion and returns a full non-streaming Result.
func (c *Completion) Result() (Result, error) {
	if err := c.validateCompleted(); err != nil {
		return Result{}, err
	}
	c.finished = true
	return Result{
		ID:      c.id,
		Object:  "chat.completion",
		Created: c.created,
		Model:   c.modelID,
		Choices: []Choice{
			{
				Index:        0,
				Message:      c.buildAssistantMessage(),
				FinishReason: c.finishReason,
			},
		},
		Usage: c.buildUsage(),
	}, nil
}

// History returns the assistant message projection and exact upstream Content
// only after Finish or Result has succeeded cleanly.
func (c *Completion) History() (Message, *pb.Content, bool) {
	if !c.finished || c.finishReason == "" {
		return Message{}, nil, false
	}
	return c.buildAssistantMessage(), proto.Clone(c.upstreamContent).(*pb.Content), true
}
