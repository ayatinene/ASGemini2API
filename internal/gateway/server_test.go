package gateway

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/aicode"
	"github.com/ayatinene/ASGemini2API/internal/aicode/pb"
	"github.com/ayatinene/ASGemini2API/internal/auth"
	"github.com/ayatinene/ASGemini2API/internal/chat"
	"github.com/ayatinene/ASGemini2API/internal/settings"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	testAPI    = "test-only-api-key-123456789"
	testAdmin  = "test-only-admin-key-123456789"
	textChat   = `{"model":"sample","messages":[{"role":"user","content":"hello"}]}`
	streamChat = `{"model":"sample","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hello"}]}`
)

type testAccount struct{ ready bool }

func (a testAccount) Status() (auth.Status, error) { return auth.Status{LoggedIn: a.ready}, nil }

func (a testAccount) BeginLogin(redirectURI string) (string, *auth.LoginAttempt, error) {
	return "https://accounts.example.invalid/o/oauth2/auth?state=test-state", &auth.LoginAttempt{
		State: "test-state", Verifier: "test-verifier", RedirectURI: redirectURI, CreatedAt: time.Now(),
	}, nil
}

func (a testAccount) CompleteLogin(_ context.Context, _ *auth.LoginAttempt, code string) (auth.Status, error) {
	if code != "test-code" {
		return auth.Status{}, &auth.Error{Code: "missing_code", Message: "authorization code is missing or invalid"}
	}
	return auth.Status{LoggedIn: true}, nil
}

type testUpstream struct {
	configs, quotas, streams atomic.Int32
	fetchConfig              func(context.Context) (*pb.FetchConfigResponse, error)
	fetchQuota               func(context.Context) (*pb.FetchQuotaStatusResponse, error)
	generate                 func(context.Context, *pb.GenerateContentRequest, func(*pb.GenerateContentResponse) error) error
}

func (u *testUpstream) FetchConfig(ctx context.Context) (*pb.FetchConfigResponse, error) {
	u.configs.Add(1)
	if u.fetchConfig != nil {
		return u.fetchConfig(ctx)
	}
	return &pb.FetchConfigResponse{AvailableExperiences: []*pb.FetchConfigResponse_Experience{
		{Name: "chat_agent_mode_sample", Model: &pb.FetchConfigResponse_Model{ModelId: "sample", DisplayName: "Sample"}},
		{Name: "chat_agent_mode_other", Model: &pb.FetchConfigResponse_Model{ModelId: "other", DisplayName: "Other"}},
	}}, nil
}

func (u *testUpstream) FetchQuota(ctx context.Context) (*pb.FetchQuotaStatusResponse, error) {
	u.quotas.Add(1)
	if u.fetchQuota != nil {
		return u.fetchQuota(ctx)
	}
	return &pb.FetchQuotaStatusResponse{Buckets: []*pb.FetchQuotaStatusResponse_BucketInfo{
		{RemainingFraction: 0.5, QuotaType: pb.FetchQuotaStatusResponse_REQUESTS, Model: &pb.Model{ModelId: "sample"}},
	}}, nil
}

func (u *testUpstream) Stream(ctx context.Context, req *pb.GenerateContentRequest, yield func(*pb.GenerateContentResponse) error) error {
	u.streams.Add(1)
	return u.generate(ctx, req, yield)
}

func testServer(u *testUpstream, ready bool) http.Handler {
	cfg := settings.Config{CatalogTTL: time.Hour, QuotaTTL: time.Minute, MaxInFlight: 2, MaxBodyBytes: 4096}
	keys := settings.Keys{API: sha256.Sum256([]byte(testAPI)), Admin: sha256.Sum256([]byte(testAdmin))}
	return New(u, testAccount{ready}, cfg, keys, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
}

func request(handler http.Handler, method, endpoint, key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, endpoint, strings.NewReader(body))
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func checkHTTP(t *testing.T, w *httptest.ResponseRecorder, want int, text string) {
	t.Helper()
	if w.Code != want || !strings.Contains(w.Body.String(), text) {
		t.Fatalf("want HTTP %d and %q; got HTTP %d: %s", want, text, w.Code, w.Body.String())
	}
}

func textFrame(text string, finish pb.FinishReason) *pb.GenerateContentResponse {
	return &pb.GenerateContentResponse{Candidates: []*pb.Candidate{{Content: &pb.Content{Role: "model", Parts: []*pb.Part{
		{Data: &pb.Part_Text{Text: text}},
	}}, FinishReason: finish}}}
}

func TestAuthDiscoveryAndManagement(t *testing.T) {
	u := &testUpstream{}
	s := testServer(u, false)
	checkHTTP(t, request(s, "GET", "/healthz", "", ""), 200, `"ok"`)
	checkHTTP(t, request(s, "GET", "/readyz", "", ""), 503, `"not_ready"`)
	checkHTTP(t, request(s, "GET", "/v1/models", "", ""), 401, "invalid_api_key")
	checkHTTP(t, request(s, "GET", "/admin/account", testAPI, ""), 401, "invalid_api_key")
	checkHTTP(t, request(s, "GET", "/admin/account", testAdmin, ""), 200, `"logged_in":false`)
	checkHTTP(t, request(s, "GET", "/admin/quota", testAdmin, ""), 200, `"remaining_fraction":0.5`)
	checkHTTP(t, request(s, "GET", "/admin/quota", testAdmin, ""), 200, `"remaining_fraction":0.5`)
	checkHTTP(t, request(s, "GET", "/admin/quota?refresh=true", testAdmin, ""), 200, `"remaining_fraction":0.5`)
	checkHTTP(t, request(s, "GET", "/v1/models", testAPI, ""), 200, `"id":"sample"`)
	checkHTTP(t, request(s, "GET", "/v1/models/sample", testAPI, ""), 200, `"object":"model"`)
	checkHTTP(t, request(s, "GET", "/v1/models/unknown", testAPI, ""), 404, `"model_not_found"`)
	checkHTTP(t, request(s, "POST", "/v1/chat/completions", testAPI, strings.Repeat("x", 4097)), 413, "request_too_large")
	if u.configs.Load() != 1 || u.quotas.Load() != 2 || u.streams.Load() != 0 {
		t.Fatalf("unexpected upstream call counts: %d %d %d", u.configs.Load(), u.quotas.Load(), u.streams.Load())
	}
}

func TestCompletionStreamingAndQuotaCooldown(t *testing.T) {
	u := &testUpstream{}
	u.generate = func(_ context.Context, r *pb.GenerateContentRequest, yield func(*pb.GenerateContentResponse) error) error {
		if r.GetAicode().GetExperience() != "chat_agent_mode_sample" || r.GetSessionId() == "" {
			t.Errorf("invalid experience/session: %q %q", r.GetAicode().GetExperience(), r.GetSessionId())
		}
		switch u.streams.Load() {
		case 1:
			frame := textFrame("OK", pb.FinishReason_STOP)
			frame.UsageMetadata = &pb.GenerateContentResponse_UsageMetadata{PromptTokenCount: 3, CandidatesTokenCount: 1}
			return yield(frame)
		case 2:
			return yield(textFrame("OK", pb.FinishReason_STOP))
		case 3:
			if err := yield(textFrame("partial", pb.FinishReason_FINISH_REASON_UNSPECIFIED)); err != nil {
				return err
			}
			return &aicode.Error{Code: codes.ResourceExhausted, RetryAfter: 2 * time.Second}
		default:
			t.Errorf("generation must not be retried; got %d", u.streams.Load())
			return errors.New("unexpected request")
		}
	}
	s := testServer(u, true)
	sse := request(s, "POST", "/v1/chat/completions", testAPI, streamChat)
	checkHTTP(t, sse, 200, "data: [DONE]\n\n")
	if !strings.Contains(sse.Body.String(), `"prompt_tokens":3`) || !strings.Contains(sse.Body.String(), `"role":"assistant"`) {
		t.Fatal(sse.Body.String())
	}
	checkHTTP(t, request(s, "POST", "/v1/chat/completions", testAPI, textChat), 200, `"content":"OK"`)
	failure := request(s, "POST", "/v1/chat/completions", testAPI, streamChat)
	checkHTTP(t, failure, 200, `"upstream_quota_exhausted"`)
	if strings.Contains(failure.Body.String(), "[DONE]") {
		t.Fatal("partial response must not be acknowledged as complete")
	}
	busy := request(s, "POST", "/v1/chat/completions", testAPI, textChat)
	checkHTTP(t, busy, 429, "upstream_quota_exhausted")
	if busy.Header().Get("Retry-After") == "" || u.streams.Load() != 3 {
		t.Fatalf("cooldown was not enforced: %v %d", busy.Header(), u.streams.Load())
	}
}

func TestCancellationAfterFlushedChunk(t *testing.T) {
	cancelled := make(chan struct{})
	u := &testUpstream{generate: func(ctx context.Context, _ *pb.GenerateContentRequest, yield func(*pb.GenerateContentResponse) error) error {
		if err := yield(textFrame("first", pb.FinishReason_FINISH_REASON_UNSPECIFIED)); err != nil {
			return err
		}
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	}}
	local := httptest.NewServer(testServer(u, true))
	defer local.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "POST", local.URL+"/v1/chat/completions", strings.NewReader(streamChat))
	r.Header.Set("Authorization", "Bearer "+testAPI)
	response, err := local.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(response.Body).ReadString('\n')
	if err != nil || !strings.Contains(line, `"first"`) {
		t.Fatalf("expected first SSE chunk while upstream still running: %q %v", line, err)
	}
	cancel()
	response.Body.Close()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("client cancellation did not reach the upstream context")
	}
}

func TestToolHistoryRetainsSignatureWithoutClientExtension(t *testing.T) {
	const signature = "opaque signature bytes"
	u := &testUpstream{}
	u.generate = func(_ context.Context, req *pb.GenerateContentRequest, yield func(*pb.GenerateContentResponse) error) error {
		if u.streams.Load() == 1 {
			args, _ := structpb.NewStruct(map[string]any{"city": "Berlin", "unit": 1.0})
			return yield(&pb.GenerateContentResponse{Candidates: []*pb.Candidate{{
				FinishReason: pb.FinishReason_STOP,
				Content: &pb.Content{Role: "model", Parts: []*pb.Part{{
					Data: &pb.Part_FunctionCall{FunctionCall: &pb.FunctionCall{Id: "call_1", Name: "weather", Args: args}}, ThoughtSignature: []byte(signature),
				}}},
			}}})
		}
		contents := req.GetContents()
		if len(contents) != 3 || len(contents[1].GetParts()) != 1 || len(contents[2].GetParts()) != 1 {
			t.Fatalf("unmatched tool history: %v", contents)
		}
		call, result := contents[1].GetParts()[0], contents[2].GetParts()[0].GetFunctionResponse()
		if call.GetFunctionCall().GetId() != "call_1" || string(call.GetThoughtSignature()) != signature ||
			result.GetId() != "call_1" || result.GetName() != "weather" || result.GetResponse().GetFields()["result"].GetStringValue() != "sunny" {
			t.Fatalf("history lost ID, result, name, or signature")
		}
		return yield(textFrame("sunny", pb.FinishReason_STOP))
	}
	s := testServer(u, true)
	original := request(s, "POST", "/v1/chat/completions", testAPI, textChat)
	checkHTTP(t, original, 200, `"finish_reason":"tool_calls"`)
	checkHTTP(t, request(s, "POST", "/v1/chat/completions", testAPI, `{"model":"sample","messages":[
		{"role":"user","content":[{"type":"text","text":"hello"}]},
		{"role":"assistant","content":"","tool_calls":[{"type":"function","id":"call_1","function":{"name":"weather","arguments":"{\"unit\":1,\"city\":\"Berlin\"}"}}]},
		{"role":"tool","tool_call_id":"call_1","content":"sunny"}]}`), 200, `"content":"sunny"`)
}

func TestCatalogCoalescesReads(t *testing.T) {
	var calls atomic.Int32
	started, proceed := make(chan struct{}), make(chan struct{})
	c := cache[int]{ttl: time.Minute, load: func(ctx context.Context) (int, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-proceed:
			return 42, nil
		}
	}}
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			got, err := c.get(t.Context(), false)
			if err != nil || got.Value != 42 {
				t.Errorf("coalesced get: %v %v", got, err)
			}
		})
	}
	<-started
	close(proceed)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("wanted 1 load, got %d", calls.Load())
	}
}

func TestUnavailableBeforeFirstChunkIsAnHTTPError(t *testing.T) {
	u := &testUpstream{generate: func(_ context.Context, _ *pb.GenerateContentRequest, _ func(*pb.GenerateContentResponse) error) error {
		return &aicode.Error{Code: codes.Unavailable}
	}}
	s := testServer(u, true)
	reply := request(s, "POST", "/v1/chat/completions", testAPI, streamChat)
	checkHTTP(t, reply, 503, "upstream_unavailable")
	var body map[string]any
	if err := json.Unmarshal(reply.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	checkHTTP(t, request(s, "POST", "/v1/chat/completions", testAPI, streamChat), 503, "upstream_cooldown")
	if u.streams.Load() != 1 {
		t.Fatal("generation should not be replayed")
	}
}

func waitForWaiters[T any](t *testing.T, c *cache[T], want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := 0
		if c.pending != nil {
			got = c.pending.waiters
		}
		c.mu.Unlock()
		if got >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d cache waiters", want)
}

func TestCatalogFirstWaiterCancelDoesNotHarmOtherWaiters(t *testing.T) {
	var calls atomic.Int32
	started, proceed, loadExited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	c := cache[int]{ttl: time.Minute, timeout: 2 * time.Second, load: func(ctx context.Context) (int, error) {
		defer close(loadExited)
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-proceed:
			return 42, nil
		}
	}}

	ctx1, cancel1 := context.WithCancel(t.Context())
	defer cancel1()
	err1Ch := make(chan error, 1)
	go func() {
		_, err := c.get(ctx1, false)
		err1Ch <- err
	}()
	<-started

	ctx2, cancel2 := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel2()
	type result struct {
		snap snapshot[int]
		err  error
	}
	res2Ch := make(chan result, 1)
	go func() {
		snap, err := c.get(ctx2, false)
		res2Ch <- result{snap: snap, err: err}
	}()

	waitForWaiters(t, &c, 2)
	cancel1()

	select {
	case err := <-err1Ch:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled for first waiter, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first waiter did not cancel promptly")
	}

	select {
	case <-loadExited:
		t.Fatal("shared load must not cancel when another waiter remains")
	default:
	}

	close(proceed)
	select {
	case res := <-res2Ch:
		if res.err != nil || res.snap.Value != 42 {
			t.Fatalf("remaining waiter failed: %+v", res)
		}
	case <-time.After(time.Second):
		t.Fatal("remaining waiter did not receive loaded value")
	}

	cached, err := c.get(t.Context(), false)
	if err != nil || cached.Value != 42 || calls.Load() != 1 {
		t.Fatalf("expected cached value 42 with 1 load, got %+v err=%v calls=%d", cached, err, calls.Load())
	}
}

func TestCatalogAllWaitersLeaveCancelsLoadAndDoesNotCache(t *testing.T) {
	var calls atomic.Int32
	started, cancelled := make(chan struct{}), make(chan struct{})
	c := cache[int]{ttl: time.Minute, timeout: 5 * time.Second, load: func(ctx context.Context) (int, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return 0, ctx.Err()
		}
		return 99, nil
	}}

	ctx1, cancel1 := context.WithCancel(t.Context())
	ctx2, cancel2 := context.WithCancel(t.Context())
	err1Ch, err2Ch := make(chan error, 1), make(chan error, 1)
	go func() { _, err := c.get(ctx1, false); err1Ch <- err }()
	<-started
	go func() { _, err := c.get(ctx2, false); err2Ch <- err }()
	waitForWaiters(t, &c, 2)

	cancel1()
	cancel2()

	for _, ch := range []chan error{err1Ch, err2Ch} {
		select {
		case err := <-ch:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context.Canceled, got %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("waiter did not exit promptly after cancellation")
		}
	}

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("shared load was not cancelled after all waiters left")
	}

	if !c.latest().FetchedAt.IsZero() {
		t.Fatal("aborted read must not populate cache")
	}

	got, err := c.get(t.Context(), false)
	if err != nil || got.Value != 99 || calls.Load() != 2 {
		t.Fatalf("expected fresh load 99 after all-waiter abort, got %+v err=%v calls=%d", got, err, calls.Load())
	}
}

func TestCatalogBoundedTimeoutSameBatchAndFailureNotCached(t *testing.T) {
	var calls atomic.Int32
	c := cache[int]{
		ttl:     time.Minute,
		timeout: 30 * time.Millisecond,
		cooldown: func(error) time.Duration {
			return 25 * time.Millisecond
		},
		load: func(ctx context.Context) (int, error) {
			if calls.Add(1) == 1 {
				<-ctx.Done()
				return 0, ctx.Err()
			}
			return 77, nil
		},
	}

	errs := make(chan error, 3)
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			_, err := c.get(t.Context(), false)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded for timed-out batch, got %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 bounded load for batch, got %d", calls.Load())
	}
	if !c.latest().FetchedAt.IsZero() {
		t.Fatal("timed-out read must not cache")
	}

	// Immediate call during failure cooldown returns the failure without calling load.
	if _, err := c.get(t.Context(), false); !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatalf("expected cooldown failure with 1 load, got err=%v calls=%d", err, calls.Load())
	}

	time.Sleep(35 * time.Millisecond)
	got, err := c.get(t.Context(), false)
	if err != nil || got.Value != 77 || calls.Load() != 2 {
		t.Fatalf("expected recovery load 77 after cooldown, got %+v err=%v calls=%d", got, err, calls.Load())
	}
}

func TestHTTPModelsAndQuotaCoalescingAndCancellation(t *testing.T) {
	started, proceed := make(chan struct{}), make(chan struct{})
	quotaStarted, quotaCancelled := make(chan struct{}), make(chan struct{})
	u := &testUpstream{
		fetchConfig: func(ctx context.Context) (*pb.FetchConfigResponse, error) {
			close(started)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-proceed:
				return &pb.FetchConfigResponse{AvailableExperiences: []*pb.FetchConfigResponse_Experience{
					{Name: "chat_agent_mode_sample", Model: &pb.FetchConfigResponse_Model{ModelId: "sample", DisplayName: "Sample"}},
				}}, nil
			}
		},
		fetchQuota: func(ctx context.Context) (*pb.FetchQuotaStatusResponse, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			select {
			case <-quotaStarted:
				return &pb.FetchQuotaStatusResponse{Buckets: []*pb.FetchQuotaStatusResponse_BucketInfo{
					{RemainingFraction: 0.75, QuotaType: pb.FetchQuotaStatusResponse_REQUESTS, Model: &pb.Model{ModelId: "sample"}},
				}}, nil
			default:
				close(quotaStarted)
				<-ctx.Done()
				close(quotaCancelled)
				return nil, ctx.Err()
			}
		},
	}

	cfg := settings.Config{CatalogTTL: time.Hour, QuotaTTL: time.Minute, UnaryTimeout: time.Second, MaxInFlight: 2, MaxBodyBytes: 4096}
	keys := settings.Keys{API: sha256.Sum256([]byte(testAPI)), Admin: sha256.Sum256([]byte(testAdmin))}
	srv := New(u, testAccount{true}, cfg, keys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := srv.Handler()

	// Request 1 cancels /v1/models while Request 2 keeps waiting and succeeds.
	ctx1, cancel1 := context.WithCancel(t.Context())
	done1 := make(chan int, 1)
	go func() {
		r := httptest.NewRequest("GET", "/v1/models", nil).WithContext(ctx1)
		r.Header.Set("Authorization", "Bearer "+testAPI)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		done1 <- w.Code
	}()
	<-started

	done2 := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done2 <- request(h, "GET", "/v1/models", testAPI, "")
	}()
	waitForWaiters(t, &srv.models, 2)
	cancel1()
	<-done1
	close(proceed)

	w2 := <-done2
	checkHTTP(t, w2, 200, `"id":"sample"`)
	if u.configs.Load() != 1 {
		t.Fatalf("expected 1 FetchConfig call, got %d", u.configs.Load())
	}

	// Single /admin/quota waiter cancels -> upstream FetchQuota context is cancelled.
	qCtx, qCancel := context.WithCancel(t.Context())
	qDone := make(chan struct{})
	go func() {
		r := httptest.NewRequest("GET", "/admin/quota?refresh=true", nil).WithContext(qCtx)
		r.Header.Set("Authorization", "Bearer "+testAdmin)
		h.ServeHTTP(httptest.NewRecorder(), r)
		close(qDone)
	}()
	<-quotaStarted
	waitForWaiters(t, &srv.quota, 1)
	qCancel()
	<-qDone
	select {
	case <-quotaCancelled:
	case <-time.After(time.Second):
		t.Fatal("FetchQuota was not cancelled when all waiters left")
	}

	// Subsequent quota read succeeds cleanly.
	checkHTTP(t, request(h, "GET", "/admin/quota", testAdmin, ""), 200, `"remaining_fraction":0.75`)
}

func TestUpstreamErrorSanitization(t *testing.T) {
	const (
		secretGuidance = "SECRET_UPSTREAM_GUIDANCE_SHOULD_NOT_LEAK"
		secretRawErr   = "SECRET_RAW_INTERNAL_DETAIL_SHOULD_NOT_LEAK"
	)

	// 1. *aicode.Error does not leak Guidance.
	u1 := &testUpstream{generate: func(_ context.Context, _ *pb.GenerateContentRequest, _ func(*pb.GenerateContentResponse) error) error {
		return &aicode.Error{
			Code:     codes.Internal,
			RPC:      "google.gca.aicode.v1.PredictionService/StreamGenerateContent",
			Reason:   "BACKEND_UNAVAILABLE",
			Domain:   "aicode.googleapis.com",
			Guidance: secretGuidance,
		}
	}}
	w1 := request(testServer(u1, true), "POST", "/v1/chat/completions", testAPI, textChat)
	checkHTTP(t, w1, 502, `"upstream_error"`)
	if strings.Contains(w1.Body.String(), secretGuidance) {
		t.Fatalf("response leaked upstream Guidance: %s", w1.Body.String())
	}

	// 2. Arbitrary error does not leak raw err.Error() before first chunk.
	u2 := &testUpstream{generate: func(_ context.Context, _ *pb.GenerateContentRequest, _ func(*pb.GenerateContentResponse) error) error {
		return errors.New(secretRawErr)
	}}
	w2 := request(testServer(u2, true), "POST", "/v1/chat/completions", testAPI, textChat)
	checkHTTP(t, w2, 500, `"internal_error"`)
	if strings.Contains(w2.Body.String(), secretRawErr) {
		t.Fatalf("response leaked raw internal error: %s", w2.Body.String())
	}

	// 3. Mid-stream SSE failure also sanitizes raw error text.
	u3 := &testUpstream{generate: func(_ context.Context, _ *pb.GenerateContentRequest, yield func(*pb.GenerateContentResponse) error) error {
		if err := yield(textFrame("ok", pb.FinishReason_FINISH_REASON_UNSPECIFIED)); err != nil {
			return err
		}
		return errors.New(secretRawErr)
	}}
	w3 := request(testServer(u3, true), "POST", "/v1/chat/completions", testAPI, streamChat)
	checkHTTP(t, w3, 200, `"internal_error"`)
	if strings.Contains(w3.Body.String(), secretRawErr) {
		t.Fatalf("SSE error event leaked raw internal error: %s", w3.Body.String())
	}
}

func TestHistorySignatureIsolationPartitionsAndSegmentation(t *testing.T) {
	const signature = "partitioned-signature"
	var seenSigs []string
	u := &testUpstream{}
	u.generate = func(_ context.Context, req *pb.GenerateContentRequest, yield func(*pb.GenerateContentResponse) error) error {
		if u.streams.Load() == 1 {
			args, _ := structpb.NewStruct(map[string]any{"q": "1"})
			return yield(&pb.GenerateContentResponse{Candidates: []*pb.Candidate{{
				FinishReason: pb.FinishReason_STOP,
				Content: &pb.Content{Role: "model", Parts: []*pb.Part{{
					Data:             &pb.Part_FunctionCall{FunctionCall: &pb.FunctionCall{Id: "call_1", Name: "search", Args: args}},
					ThoughtSignature: []byte(signature),
				}}},
			}}})
		}
		seenSigs = append(seenSigs, string(req.GetContents()[1].GetParts()[0].GetThoughtSignature()))
		return yield(textFrame("done", pb.FinishReason_STOP))
	}
	s := testServer(u, true)

	// Turn 1: user="alice", X-Studio-Conversation-Id="conv-1", model="sample".
	r1 := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"sample","user":"alice","messages":[{"role":"user","content":"a\nb"}]}`))
	r1.Header.Set("Authorization", "Bearer "+testAPI)
	r1.Header.Set("X-Studio-Conversation-Id", "conv-1")
	w1 := httptest.NewRecorder()
	s.ServeHTTP(w1, r1)
	checkHTTP(t, w1, 200, `"finish_reason":"tool_calls"`)

	sendTurn2 := func(model, user, conv, userContentJSON string) {
		body := `{"model":"` + model + `","user":"` + user + `","messages":[` +
			`{"role":"user","content":` + userContentJSON + `},` +
			`{"role":"assistant","content":"","tool_calls":[{"type":"function","id":"call_1","function":{"name":"search","arguments":"{\"q\":\"1\"}"}}]},` +
			`{"role":"tool","tool_call_id":"call_1","content":"ok"}]}`
		r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+testAPI)
		r.Header.Set("X-Studio-Conversation-Id", conv)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		checkHTTP(t, w, 200, `"content":"done"`)
	}

	// Cross-user, cross-conversation, cross-model, and split user parts must NOT hit alice's cache.
	sendTurn2("sample", "bob", "conv-1", `"a\nb"`)
	sendTurn2("sample", "alice", "conv-2", `"a\nb"`)
	sendTurn2("other", "alice", "conv-1", `"a\nb"`)
	sendTurn2("sample", "alice", "conv-1", `[{"type":"text","text":"a"},{"type":"text","text":"b"}]`)
	// Matching partition + single text part equivalent must restore the signature.
	sendTurn2("sample", "alice", "conv-1", `[{"type":"text","text":"a\nb"}]`)

	want := []string{"", "", "", "", signature}
	if len(seenSigs) != len(want) {
		t.Fatalf("unexpected call count: %v", seenSigs)
	}
	for i := range want {
		if seenSigs[i] != want[i] {
			t.Fatalf("case %d: got signature %q, want %q (all=%v)", i, seenSigs[i], want[i], seenSigs)
		}
	}

	// Direct history unit checks: role isolation, assistant multi-part joining, user part separation, collision tombstones.
	h := newHistory()
	sigA := &pb.Content{Role: "model", Parts: []*pb.Part{{ThoughtSignature: []byte("sigA"), Data: &pb.Part_Text{Text: "ok"}}}}
	sigB := &pb.Content{Role: "model", Parts: []*pb.Part{{ThoughtSignature: []byte("sigB"), Data: &pb.Part_Text{Text: "other"}}}}

	userSplit := []chat.Message{{Role: "user", Content: []chat.ContentPart{{Type: "text", Text: "a"}, {Type: "text", Text: "b"}}}}
	v1 := h.view("m", "exp", "u", "c", userSplit)
	v1.remember(chat.Message{Role: "assistant", Content: "ok"}, sigA)

	if got := h.view("m", "exp", "u", "c", []chat.Message{{Role: "user", Content: "a\nb"}, {Role: "assistant", Content: "ok"}}).restore(1, chat.Message{}); got != nil {
		t.Fatalf("user joined string unexpectedly matched split user parts: %v", got)
	}
	if got := h.view("m", "exp", "u", "c", []chat.Message{userSplit[0], {Role: "assistant", Content: "ok"}}).restore(1, chat.Message{}); got == nil || string(got.GetParts()[0].GetThoughtSignature()) != "sigA" {
		t.Fatalf("matching split user parts did not restore sigA: %v", got)
	}

	// Assistant multi-part text joins with "\n" (matching chat.go extractTextOnlyContent), while role differs from user.
	asstMulti := []chat.Message{
		{Role: "user", Content: "go"},
		{Role: "assistant", Content: []chat.ContentPart{{Type: "text", Text: "x"}, {Type: "text", Text: "y"}}},
	}
	v2 := h.view("m", "exp", "u", "c", []chat.Message{{Role: "user", Content: "go"}})
	v2.remember(asstMulti[1], sigA)
	if got := h.view("m", "exp", "u", "c", []chat.Message{{Role: "user", Content: "go"}, {Role: "assistant", Content: "x\ny"}}).restore(1, chat.Message{}); got == nil {
		t.Fatal("assistant joined string should match multi-part assistant text")
	}

	// Collision on same key invalidates instead of picking an arbitrary Content.
	v2Dup := h.view("m", "exp", "u", "c", []chat.Message{{Role: "user", Content: "go"}})
	v2Dup.remember(asstMulti[1], sigB)
	if got := h.view("m", "exp", "u", "c", asstMulti).restore(1, chat.Message{}); got != nil {
		t.Fatalf("colliding history key must invalidate entry, got %v", got)
	}
}

func TestHTTPRejectsStrictMode(t *testing.T) {
	u := &testUpstream{}
	s := testServer(u, true)

	toolStrict := `{"model":"sample","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"fn","parameters":{"type":"object"},"strict":true}}]}`
	checkHTTP(t, request(s, "POST", "/v1/chat/completions", testAPI, toolStrict), 400, `"unsupported_parameter"`)

	schemaStrict := `{"model":"sample","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"out","schema":{"type":"object"},"strict":true}}}`
	checkHTTP(t, request(s, "POST", "/v1/chat/completions", testAPI, schemaStrict), 400, `"unsupported_parameter"`)

	if u.streams.Load() != 0 {
		t.Fatalf("strict:true requests must be rejected before upstream stream, got %d streams", u.streams.Load())
	}
}
