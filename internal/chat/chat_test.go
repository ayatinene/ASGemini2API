package chat

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ayatinene/ASGemini2API/internal/aicode"
	pb "github.com/ayatinene/ASGemini2API/internal/aicode/pb"
	"google.golang.org/protobuf/types/known/structpb"
)

func testModel() aicode.Model {
	return aicode.Model{
		ID:               "gemini-test",
		Experience:       "chat_agent_mode",
		DisplayName:      "Gemini Test",
		OutputTokenLimit: 8192,
		ThinkingLevels:   []string{"minimal", "low", "medium", "high"},
		Features: []string{
			"FUNCTION_CALLING",
			"THINKING",
			"THINKING_LEVEL",
			"TOP_P",
			"IMAGE_INPUT",
			"JSON_SCHEMA_OUTPUT",
		},
	}
}

func assertChatErrorParam(t *testing.T, err error, wantParam string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected *Error (param=%q), got nil", wantParam)
	}
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if wantParam != "" && ce.Param != wantParam {
		t.Fatalf("expected Error.Param=%q, got %q (msg=%q)", wantParam, ce.Param, ce.Message)
	}
}

func TestDecodeIgnoresUnknownClientFieldsAndRejectsBadJSON(t *testing.T) {
	raw := `{
		"model": "gemini-test",
		"store": true,
		"metadata": {"trace": "1"},
		"stream_options": {"include_usage": true},
		"messages": [
			{"role": "user", "content": "hi"},
			{
				"role": "assistant",
				"content": null,
				"reasoning_content": "hmm",
				"extra_content": {"google": {"thought_signature": "c2ln"}},
				"tool_calls": [{
					"id": "c1",
					"type": "function",
					"function": {"name": "fn", "arguments": "{}"},
					"extra_content": {"google": {"thought_signature": "Y2FsbA=="}}
				}]
			},
			{"role": "tool", "tool_call_id": "c1", "content": "ok"}
		]
	}`
	req, err := Decode(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected Decode error: %v", err)
	}
	if req.StreamOptions == nil || !req.StreamOptions.IncludeUsage {
		t.Fatalf("expected StreamOptions.IncludeUsage=true, got %+v", req.StreamOptions)
	}
	if len(req.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(req.Messages))
	}
	asst := req.Messages[1]
	if asst.ReasoningContent != "hmm" || asst.ExtraContent == nil || asst.ExtraContent.Google == nil || asst.ExtraContent.Google.ThoughtSignature != "c2ln" {
		t.Fatalf("assistant extensions not preserved: %+v", asst)
	}
	if len(asst.ToolCalls) != 1 || asst.ToolCalls[0].ExtraContent.Google.ThoughtSignature != "Y2FsbA==" {
		t.Fatalf("tool_call extra_content not preserved: %+v", asst.ToolCalls)
	}

	for _, bad := range []string{"", "null", "[]", `{"messages":[]}{}`, `{"messages":"bad"}`} {
		if _, err := Decode(strings.NewReader(bad)); err == nil {
			t.Fatalf("expected Decode failure for %q", bad)
		}
	}
}

func TestEncodeSystemDeveloperCoalescingAndNoUseCase(t *testing.T) {
	temp := 0.5
	topP := 0.9
	maxTok := 512
	n := 1
	req := &Request{
		Model: "gemini-test",
		Messages: []Message{
			{Role: "system", Content: "Be concise."},
			{Role: "developer", Content: []ContentPart{{Type: "text", Text: "Use Go."}}},
			{Role: "user", Content: "Part 1"},
			{Role: "user", Content: []ContentPart{{Type: "text", Text: "Part 2"}}},
		},
		Temperature: &temp,
		TopP:        &topP,
		MaxTokens:   &maxTok,
		Stop:        []string{"END", "STOP"},
		N:           &n,
	}

	pbReq, err := Encode(req, testModel(), "sess-1", nil)
	if err != nil {
		t.Fatalf("unexpected Encode error: %v", err)
	}
	if pbReq.GetAicode().GetExperience() != "chat_agent_mode" {
		t.Fatalf("unexpected experience: %q", pbReq.GetAicode().GetExperience())
	}
	if pbReq.GetSessionId() != "sess-1" {
		t.Fatalf("unexpected session_id: %q", pbReq.GetSessionId())
	}
	if len(pbReq.GetLabels()) != 0 {
		t.Fatalf("expected no labels, got %v", pbReq.GetLabels())
	}
	if pbReq.GetSystemInstruction() == nil || pbReq.GetSystemInstruction().GetRole() != "user" {
		t.Fatalf("expected user-role system_instruction, got %+v", pbReq.GetSystemInstruction())
	}
	if got := pbReq.GetSystemInstruction().GetParts()[0].GetText(); got != "Be concise.\n\nUse Go." {
		t.Fatalf("unexpected system_instruction text: %q", got)
	}
	if len(pbReq.GetContents()) != 1 || pbReq.GetContents()[0].GetRole() != "user" {
		t.Fatalf("expected 1 coalesced user Content, got %+v", pbReq.GetContents())
	}
	parts := pbReq.GetContents()[0].GetParts()
	if len(parts) != 2 || parts[0].GetText() != "Part 1" || parts[1].GetText() != "Part 2" {
		t.Fatalf("unexpected coalesced user parts: %+v", parts)
	}
}

func TestEncodeThinkingLevelSymbolicAndValidation(t *testing.T) {
	cases := map[string]pb.GenerationConfig_ThinkingConfig_ThinkingLevel{
		"low":     pb.GenerationConfig_ThinkingConfig_LOW,
		"medium":  pb.GenerationConfig_ThinkingConfig_MEDIUM,
		"high":    pb.GenerationConfig_ThinkingConfig_HIGH,
		"minimal": pb.GenerationConfig_ThinkingConfig_MINIMAL,
	}
	for effort, want := range cases {
		e := effort
		pbReq, err := Encode(&Request{
			Messages:        []Message{{Role: "user", Content: "hi"}},
			ReasoningEffort: &e,
		}, testModel(), "s", nil)
		if err != nil {
			t.Fatalf("effort %q failed: %v", effort, err)
		}
		tc := pbReq.GetGenerationConfig().GetThinkingConfig()
		if tc == nil || !tc.GetIncludeThoughts() || tc.GetThinkingLevel() != want {
			t.Fatalf("effort %q: got %+v, want level %v", effort, tc, want)
		}
	}

	restricted := testModel()
	restricted.ThinkingLevels = []string{"low"}
	high := "high"
	_, err := Encode(&Request{
		Messages:        []Message{{Role: "user", Content: "hi"}},
		ReasoningEffort: &high,
	}, restricted, "s", nil)
	assertChatErrorParam(t, err, "reasoning_effort")

	xhigh := "xhigh"
	_, err = Encode(&Request{
		Messages:        []Message{{Role: "user", Content: "hi"}},
		ReasoningEffort: &xhigh,
	}, testModel(), "s", nil)
	assertChatErrorParam(t, err, "reasoning_effort")
}

func TestEncodeToolsJSONSchemaToolChoiceAndInlineImages(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"city":  map[string]any{"type": "string"},
			"units": map[string]any{"type": []string{"string", "null"}},
		},
		"additionalProperties": false,
	}
	imgB64 := base64.StdEncoding.EncodeToString([]byte("png-data"))
	req := &Request{
		Messages: []Message{
			{
				Role: "user",
				Content: []ContentPart{
					{Type: "text", Text: "check"},
					{Type: "image_url", ImageURL: &ImageURL{URL: "data:image/png;base64," + imgB64}},
				},
			},
		},
		Tools: []Tool{
			{
				Type: "function",
				Function: FunctionDefinition{
					Name:        "get_weather",
					Description: "Lookup",
					Parameters:  schema,
				},
			},
		},
		ToolChoice: map[string]any{
			"type":     "function",
			"function": map[string]any{"name": "get_weather"},
		},
	}
	pbReq, err := Encode(req, testModel(), "s", nil)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	fd := pbReq.GetTools()[0].GetFunctionDeclarations()[0]
	if fd.GetParametersJsonSchema() == nil {
		t.Fatalf("expected parameters_json_schema to be set")
	}
	gotSchema := fd.GetParametersJsonSchema().AsInterface().(map[string]any)
	if gotSchema["additionalProperties"] != false {
		t.Fatalf("expected additionalProperties=false preserved, got %v", gotSchema)
	}
	fcc := pbReq.GetToolConfig().GetFunctionCallingConfig()
	if fcc.GetMode() != pb.FunctionCallingConfig_ANY || len(fcc.GetAllowedFunctionNames()) != 1 || fcc.GetAllowedFunctionNames()[0] != "get_weather" {
		t.Fatalf("unexpected tool_config: %+v", fcc)
	}
	imgPart := pbReq.GetContents()[0].GetParts()[1].GetInlineData()
	if imgPart.GetMimeType() != "image/png" || string(imgPart.GetData()) != "png-data" {
		t.Fatalf("unexpected inline image: %+v", imgPart)
	}

	// Reject remote HTTP image URL (no SSRF)
	_, err = Encode(&Request{
		Messages: []Message{
			{
				Role: "user",
				Content: []ContentPart{
					{Type: "image_url", ImageURL: &ImageURL{URL: "https://example.com/x.png"}},
				},
			},
		},
	}, testModel(), "s", nil)
	assertChatErrorParam(t, err, "messages")

	// Fallback model with empty Features must not block tools
	fallback := aicode.Model{ID: "studio-default", Experience: "chat_agent_mode", Fallback: true}
	if _, err := Encode(&Request{
		Messages: []Message{{Role: "user", Content: "hi"}},
		Tools:    req.Tools,
	}, fallback, "s", nil); err != nil {
		t.Fatalf("expected fallback model to allow tools, got %v", err)
	}
}

func TestEncodeRestoreCallbackAndParallelToolOrdering(t *testing.T) {
	restored := &pb.Content{
		Role: "model",
		Parts: []*pb.Part{
			{
				Thought:          true,
				ThoughtSignature: []byte("sig-thought"),
				Data:             &pb.Part_Text{Text: "private thought"},
			},
			{
				ThoughtSignature: []byte("sig-c1"),
				Data: &pb.Part_FunctionCall{
					FunctionCall: &pb.FunctionCall{Id: "c1", Name: "fn_a"},
				},
			},
			{
				Data: &pb.Part_FunctionCall{
					FunctionCall: &pb.FunctionCall{Id: "c2", Name: "fn_b"},
				},
			},
		},
	}

	req := &Request{
		Messages: []Message{
			{Role: "user", Content: "run"},
			{
				Role:    "assistant",
				Content: nil,
				ToolCalls: []ToolCall{
					{ID: "c1", Type: "function", Function: FunctionCall{Name: "fn_a", Arguments: "{}"}},
					{ID: "c2", Type: "function", Function: FunctionCall{Name: "fn_b", Arguments: "{}"}},
				},
			},
			{Role: "tool", ToolCallID: "c2", Content: "res-b"},
			{Role: "tool", ToolCallID: "c1", Content: "res-a"},
			{Role: "user", Content: "next"},
		},
	}

	var restoredIdx int
	pbReq, err := Encode(req, testModel(), "s", func(index int, msg Message) *pb.Content {
		restoredIdx = index
		return restored
	})
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if restoredIdx != 1 {
		t.Fatalf("expected restore called at index 1, got %d", restoredIdx)
	}
	if len(pbReq.GetContents()) != 3 {
		t.Fatalf("expected 3 contents, got %d", len(pbReq.GetContents()))
	}
	modelParts := pbReq.GetContents()[1].GetParts()
	if len(modelParts) != 3 || !modelParts[0].GetThought() || string(modelParts[0].GetThoughtSignature()) != "sig-thought" {
		t.Fatalf("restored model parts mismatch: %+v", modelParts)
	}
	if string(modelParts[1].GetThoughtSignature()) != "sig-c1" || len(modelParts[2].GetThoughtSignature()) != 0 {
		t.Fatalf("signature attached to wrong call part: %+v", modelParts)
	}

	userParts := pbReq.GetContents()[2].GetParts()
	if len(userParts) != 3 {
		t.Fatalf("expected 3 coalesced user parts, got %d", len(userParts))
	}
	if userParts[0].GetFunctionResponse().GetId() != "c1" || userParts[1].GetFunctionResponse().GetId() != "c2" {
		t.Fatalf("expected tool responses ordered [c1, c2], got [%s, %s]",
			userParts[0].GetFunctionResponse().GetId(),
			userParts[1].GetFunctionResponse().GetId(),
		)
	}
	if got := userParts[0].GetFunctionResponse().GetResponse().AsMap()["result"]; got != "res-a" {
		t.Fatalf("unexpected response.result: %v", got)
	}
	if userParts[2].GetText() != "next" {
		t.Fatalf("expected trailing user text, got %+v", userParts[2])
	}
}

func TestEncodeRejectsMalformedHistory(t *testing.T) {
	badCases := [][]Message{
		{{Role: "tool", ToolCallID: "c1", Content: "orphan"}},
		{{Role: "user", Content: "hi"}, {Role: "tool", ToolCallID: "c1", Content: "orphan"}},
		{
			{Role: "user", Content: "hi"},
			{Role: "assistant", Content: nil, ToolCalls: []ToolCall{
				{ID: "c1", Type: "function", Function: FunctionCall{Name: "f", Arguments: "{}"}},
				{ID: "c2", Type: "function", Function: FunctionCall{Name: "g", Arguments: "{}"}},
			}},
			{Role: "tool", ToolCallID: "c1", Content: "only one"},
		},
		{
			{Role: "user", Content: "hi"},
			{Role: "assistant", Content: nil, ToolCalls: []ToolCall{
				{ID: "c1", Type: "function", Function: FunctionCall{Name: "f", Arguments: "{}"}},
			}},
			{Role: "tool", ToolCallID: "c1", Content: "one"},
			{Role: "tool", ToolCallID: "c1", Content: "dup"},
		},
		{
			{Role: "user", Content: "hi"},
			{Role: "assistant", Content: nil, ToolCalls: []ToolCall{
				{ID: "c1", Type: "function", Function: FunctionCall{Name: "f", Arguments: "[1,2]"}},
			}},
			{Role: "tool", ToolCallID: "c1", Content: "ok"},
		},
		{
			{Role: "user", Content: "hi"},
			{Role: "assistant", Content: "bad", ExtraContent: &ExtraContent{Google: &GoogleExtraContent{ThoughtSignature: "!!!"}}},
		},
		{{Role: "system", Content: "only system"}},
	}

	for i, msgs := range badCases {
		_, err := Encode(&Request{Messages: msgs}, testModel(), "s", nil)
		assertChatErrorParam(t, err, "messages")
		_ = i
	}
}

func TestCompletionStreamingToolCallsHistoryAndErrors(t *testing.T) {
	if !PushEmitsInitialRole {
		t.Fatal("expected PushEmitsInitialRole to be true")
	}

	comp := NewCompletion("gemini-test", true)
	if _, _, ok := comp.History(); ok {
		t.Fatal("History() must be false before Finish/Result")
	}

	argsStruct, err := structpb.NewStruct(map[string]any{"q": "hello"})
	if err != nil {
		t.Fatal(err)
	}

	chunks1, err := comp.Push(&pb.GenerateContentResponse{
		Candidates: []*pb.Candidate{
			{
				Content: &pb.Content{
					Role: "model",
					Parts: []*pb.Part{
						{Thought: true, Data: &pb.Part_Text{Text: "thinking"}},
					},
				},
			},
		},
		UsageMetadata: &pb.GenerateContentResponse_UsageMetadata{PromptTokenCount: 10},
	})
	if err != nil {
		t.Fatalf("Push 1 failed: %v", err)
	}
	if len(chunks1) != 1 || chunks1[0].Choices[0].Delta.Role != "assistant" || chunks1[0].Choices[0].Delta.ReasoningContent != "thinking" {
		t.Fatalf("unexpected chunk 1: %+v", chunks1)
	}

	chunks2, err := comp.Push(&pb.GenerateContentResponse{
		Candidates: []*pb.Candidate{
			{
				FinishReason: pb.FinishReason_STOP,
				Content: &pb.Content{
					Role: "model",
					Parts: []*pb.Part{
						{
							ThoughtSignature: []byte("sig-fc"),
							Data: &pb.Part_FunctionCall{
								FunctionCall: &pb.FunctionCall{Name: "search", Args: argsStruct},
							},
						},
					},
				},
			},
		},
		UsageMetadata: &pb.GenerateContentResponse_UsageMetadata{
			CandidatesTokenCount: 5,
			ThoughtsTokenCount:   3,
			TotalTokenCount:      18,
		},
	})
	if err != nil {
		t.Fatalf("Push 2 failed: %v", err)
	}
	if len(chunks2) != 1 || len(chunks2[0].Choices[0].Delta.ToolCalls) != 1 {
		t.Fatalf("unexpected chunk 2: %+v", chunks2)
	}
	tc := chunks2[0].Choices[0].Delta.ToolCalls[0]
	if tc.ID == "" || tc.Index == nil || *tc.Index != 0 {
		t.Fatalf("expected generated UUID and index 0, got %+v", tc)
	}
	var parsedArgs map[string]any
	if err := json.Unmarshal([]byte(tc.Function.Arguments), &parsedArgs); err != nil || parsedArgs["q"] != "hello" {
		t.Fatalf("unexpected tool arguments %q: %v", tc.Function.Arguments, err)
	}
	if tc.ExtraContent == nil || tc.ExtraContent.Google == nil || tc.ExtraContent.Google.ThoughtSignature != base64.StdEncoding.EncodeToString([]byte("sig-fc")) {
		t.Fatalf("missing tool call signature: %+v", tc.ExtraContent)
	}

	fin, err := comp.Finish()
	if err != nil {
		t.Fatalf("Finish failed: %v", err)
	}
	if len(fin) != 2 || *fin[0].Choices[0].FinishReason != "tool_calls" {
		t.Fatalf("unexpected finish chunks: %+v", fin)
	}
	if len(fin[1].Choices) != 0 || fin[1].Usage == nil || fin[1].Usage.CompletionTokens != 8 || fin[1].Usage.TotalTokens != 18 {
		t.Fatalf("unexpected usage chunk: %+v", fin[1])
	}

	// Pinned ID and Created across chunks and Result
	res, err := comp.Result()
	if err != nil {
		t.Fatalf("Result failed: %v", err)
	}
	if res.ID != chunks1[0].ID || res.Created != chunks1[0].Created || res.Choices[0].FinishReason != "tool_calls" {
		t.Fatalf("pinned id/created mismatch: chunk=%+v res=%+v", chunks1[0], res)
	}
	if res.Choices[0].Message.Content != nil {
		t.Fatalf("expected nil Content for tool-call-only message, got %v", res.Choices[0].Message.Content)
	}

	proj, content, ok := comp.History()
	if !ok {
		t.Fatal("expected History() true after Finish/Result")
	}
	if content.GetParts()[1].GetFunctionCall().GetId() != tc.ID || proj.ToolCalls[0].ID != tc.ID {
		t.Fatalf("History() UUID mismatch: proj=%q proto=%q", proj.ToolCalls[0].ID, content.GetParts()[1].GetFunctionCall().GetId())
	}

	// Missing semantic finish -> terminal 502 error and no History()
	incomplete := NewCompletion("gemini-test", false)
	if _, err := incomplete.Push(&pb.GenerateContentResponse{
		Candidates: []*pb.Candidate{{Content: &pb.Content{Role: "model", Parts: []*pb.Part{{Data: &pb.Part_Text{Text: "partial"}}}}}},
	}); err != nil {
		t.Fatal(err)
	}
	_, err = incomplete.Finish()
	var ce *Error
	if !errors.As(err, &ce) || ce.Status != 502 {
		t.Fatalf("expected 502 *Error on missing finish, got %v", err)
	}
	if _, _, ok := incomplete.History(); ok {
		t.Fatal("History() must remain false after failed Finish")
	}
}

func TestEncodeStrictModeContract(t *testing.T) {
	strictTrue := true
	strictFalse := false
	schema := map[string]any{
		"type":       "object",
		"properties": map[string]any{"ok": map[string]any{"type": "boolean"}},
	}

	// tools[].function.strict: true must be rejected via unsupported_parameter.
	rawToolStrict := `{
		"model": "gemini-test",
		"messages": [{"role": "user", "content": "hi"}],
		"tools": [{
			"type": "function",
			"function": {"name": "lookup", "parameters": {"type": "object"}, "strict": true}
		}]
	}`
	req, err := Decode(strings.NewReader(rawToolStrict))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	_, err = Encode(req, testModel(), "s", nil)
	assertChatErrorParam(t, err, "tools")
	var ce *Error
	if !errors.As(err, &ce) || ce.Code != "unsupported_parameter" || ce.Status != 400 {
		t.Fatalf("expected 400 unsupported_parameter for strict tool, got %+v", err)
	}

	// tools[].function.strict: false is accepted.
	if _, err := Encode(&Request{
		Messages: []Message{{Role: "user", Content: "hi"}},
		Tools: []Tool{{
			Type:     "function",
			Function: FunctionDefinition{Name: "lookup", Parameters: schema, Strict: &strictFalse},
		}},
	}, testModel(), "s", nil); err != nil {
		t.Fatalf("expected strict=false tool to succeed, got %v", err)
	}

	// response_format.json_schema.strict: true must be rejected via unsupported_parameter.
	rawSchemaStrict := `{
		"model": "gemini-test",
		"messages": [{"role": "user", "content": "hi"}],
		"response_format": {
			"type": "json_schema",
			"json_schema": {"name": "out", "schema": {"type": "object"}, "strict": true}
		}
	}`
	req, err = Decode(strings.NewReader(rawSchemaStrict))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	_, err = Encode(req, testModel(), "s", nil)
	assertChatErrorParam(t, err, "response_format")
	if !errors.As(err, &ce) || ce.Code != "unsupported_parameter" || ce.Status != 400 {
		t.Fatalf("expected 400 unsupported_parameter for strict json_schema, got %+v", err)
	}

	// Stray strict=true even on non-json_schema type must not be silently accepted.
	_, err = Encode(&Request{
		Messages: []Message{{Role: "user", Content: "hi"}},
		ResponseFormat: &ResponseFormat{
			Type:       "text",
			JSONSchema: &JSONSchemaFormat{Strict: &strictTrue},
		},
	}, testModel(), "s", nil)
	assertChatErrorParam(t, err, "response_format")

	// response_format.json_schema.strict: false is accepted.
	if _, err := Encode(&Request{
		Messages: []Message{{Role: "user", Content: "hi"}},
		ResponseFormat: &ResponseFormat{
			Type:       "json_schema",
			JSONSchema: &JSONSchemaFormat{Name: "out", Schema: schema, Strict: &strictFalse},
		},
	}, testModel(), "s", nil); err != nil {
		t.Fatalf("expected strict=false json_schema to succeed, got %v", err)
	}
}

func TestCompletionRejectsDuplicateToolIDsAndMalformedParts(t *testing.T) {
	// Duplicate tool ID within the same response frame.
	comp := NewCompletion("gemini-test", false)
	_, err := comp.Push(&pb.GenerateContentResponse{
		Candidates: []*pb.Candidate{{
			Content: &pb.Content{
				Role: "model",
				Parts: []*pb.Part{
					{Data: &pb.Part_FunctionCall{FunctionCall: &pb.FunctionCall{Id: "dup_1", Name: "fn_a"}}},
					{Data: &pb.Part_FunctionCall{FunctionCall: &pb.FunctionCall{Id: "dup_1", Name: "fn_b"}}},
				},
			},
		}},
	})
	var ce *Error
	if !errors.As(err, &ce) || ce.Status != 502 {
		t.Fatalf("expected 502 *Error on duplicate tool ID in same frame, got %v", err)
	}

	// Duplicate tool ID across separate frames.
	compCross := NewCompletion("gemini-test", false)
	if _, err := compCross.Push(&pb.GenerateContentResponse{
		Candidates: []*pb.Candidate{{
			Content: &pb.Content{
				Role:  "model",
				Parts: []*pb.Part{{Data: &pb.Part_FunctionCall{FunctionCall: &pb.FunctionCall{Id: "dup_2", Name: "fn_a"}}}},
			},
		}},
	}); err != nil {
		t.Fatalf("first Push failed: %v", err)
	}
	_, err = compCross.Push(&pb.GenerateContentResponse{
		Candidates: []*pb.Candidate{{
			Content: &pb.Content{
				Role:  "model",
				Parts: []*pb.Part{{Data: &pb.Part_FunctionCall{FunctionCall: &pb.FunctionCall{Id: "dup_2", Name: "fn_b"}}}},
			},
		}},
	})
	if !errors.As(err, &ce) || ce.Status != 502 {
		t.Fatalf("expected 502 *Error on duplicate tool ID across frames, got %v", err)
	}

	// Unexpected role must be rejected without echoing the raw upstream role string.
	const secretRole = "secret_upstream_role_xyz"
	compRole := NewCompletion("gemini-test", false)
	_, err = compRole.Push(&pb.GenerateContentResponse{
		Candidates: []*pb.Candidate{{
			Content: &pb.Content{
				Role:  secretRole,
				Parts: []*pb.Part{{Data: &pb.Part_Text{Text: "hi"}}},
			},
		}},
	})
	if !errors.As(err, &ce) || ce.Status != 502 {
		t.Fatalf("expected 502 *Error on unexpected role, got %v", err)
	}
	if strings.Contains(ce.Message, secretRole) {
		t.Fatalf("error message leaked raw upstream role: %q", ce.Message)
	}

	// Nil and typed-nil part guards must return 502 *Error without panicking.
	malformedParts := []*pb.Part{
		nil,
		{Data: (*pb.Part_Text)(nil)},
		{Data: (*pb.Part_FunctionCall)(nil)},
	}
	for i, part := range malformedParts {
		c := NewCompletion("gemini-test", false)
		_, err := c.Push(&pb.GenerateContentResponse{
			Candidates: []*pb.Candidate{{
				Content: &pb.Content{Role: "model", Parts: []*pb.Part{part}},
			}},
		})
		if !errors.As(err, &ce) || ce.Status != 502 {
			t.Fatalf("case %d: expected 502 *Error for malformed part, got %v", i, err)
		}
	}
}

func TestEncodeRejectsDuplicateToolIDsAndInvalidRestoredContent(t *testing.T) {
	// Fallback assistant message with duplicate tool_call IDs.
	_, err := Encode(&Request{
		Messages: []Message{
			{Role: "user", Content: "hi"},
			{
				Role: "assistant",
				ToolCalls: []ToolCall{
					{ID: "dup_id", Type: "function", Function: FunctionCall{Name: "a", Arguments: "{}"}},
					{ID: "dup_id", Type: "function", Function: FunctionCall{Name: "b", Arguments: "{}"}},
				},
			},
			{Role: "tool", ToolCallID: "dup_id", Content: "ok"},
		},
	}, testModel(), "s", nil)
	assertChatErrorParam(t, err, "messages")

	// Restored content with duplicate function call IDs.
	baseReq := &Request{
		Messages: []Message{
			{Role: "user", Content: "hi"},
			{
				Role: "assistant",
				ToolCalls: []ToolCall{
					{ID: "c1", Type: "function", Function: FunctionCall{Name: "a", Arguments: "{}"}},
					{ID: "c1", Type: "function", Function: FunctionCall{Name: "b", Arguments: "{}"}},
				},
			},
			{Role: "tool", ToolCallID: "c1", Content: "ok"},
		},
	}
	_, err = Encode(baseReq, testModel(), "s", func(int, Message) *pb.Content {
		return &pb.Content{
			Role: "model",
			Parts: []*pb.Part{
				{Data: &pb.Part_FunctionCall{FunctionCall: &pb.FunctionCall{Id: "c1", Name: "a"}}},
				{Data: &pb.Part_FunctionCall{FunctionCall: &pb.FunctionCall{Id: "c1", Name: "b"}}},
			},
		}
	})
	assertChatErrorParam(t, err, "messages")

	// Restored content with nil part, missing call ID, and mismatched tool_call type.
	badRestored := []*pb.Content{
		{Role: "model", Parts: []*pb.Part{nil}},
		{Role: "model", Parts: []*pb.Part{{Data: &pb.Part_FunctionCall{FunctionCall: &pb.FunctionCall{Id: "", Name: "a"}}}}},
	}
	singleCallReq := &Request{
		Messages: []Message{
			{Role: "user", Content: "hi"},
			{
				Role: "assistant",
				ToolCalls: []ToolCall{
					{ID: "c1", Type: "function", Function: FunctionCall{Name: "a", Arguments: "{}"}},
				},
			},
			{Role: "tool", ToolCallID: "c1", Content: "ok"},
		},
	}
	for i, restored := range badRestored {
		_, err := Encode(singleCallReq, testModel(), "s", func(int, Message) *pb.Content { return restored })
		assertChatErrorParam(t, err, "messages")
		_ = i
	}

	// Mismatched tool_call type against valid restored content.
	badTypeReq := &Request{
		Messages: []Message{
			{Role: "user", Content: "hi"},
			{
				Role: "assistant",
				ToolCalls: []ToolCall{
					{ID: "c1", Type: "custom", Function: FunctionCall{Name: "a", Arguments: "{}"}},
				},
			},
			{Role: "tool", ToolCallID: "c1", Content: "ok"},
		},
	}
	_, err = Encode(badTypeReq, testModel(), "s", func(int, Message) *pb.Content {
		return &pb.Content{
			Role:  "model",
			Parts: []*pb.Part{{Data: &pb.Part_FunctionCall{FunctionCall: &pb.FunctionCall{Id: "c1", Name: "a"}}}},
		}
	})
	assertChatErrorParam(t, err, "messages")
}
