package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/aicode"
	"github.com/ayatinene/ASGemini2API/internal/aicode/pb"
	"github.com/ayatinene/ASGemini2API/internal/auth"
	"github.com/ayatinene/ASGemini2API/internal/chat"
	"github.com/ayatinene/ASGemini2API/internal/settings"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

const maxReplyBytes = 16 << 20

type Upstream interface {
	FetchConfig(context.Context) (*pb.FetchConfigResponse, error)
	FetchQuota(context.Context) (*pb.FetchQuotaStatusResponse, error)
	Stream(context.Context, *pb.GenerateContentRequest, func(*pb.GenerateContentResponse) error) error
}

type Account interface {
	Status() (auth.Status, error)
	BeginLogin(redirectURI string) (string, *auth.LoginAttempt, error)
	CompleteLogin(ctx context.Context, attempt *auth.LoginAttempt, code string) (auth.Status, error)
}

type Server struct {
	upstream      Upstream
	account       Account
	cfg           settings.Config
	keys          settings.Keys
	log           *slog.Logger
	sessionID     string
	cacheHistory  *history
	models        cache[[]aicode.Model]
	quota         cache[[]aicode.QuotaBucket]
	bodies, slots chan struct{}
	now           func() time.Time

	mu          sync.Mutex
	globalUntil time.Time
	modelUntil  map[string]time.Time

	loginMu      sync.Mutex
	loginAttempt *auth.LoginAttempt
	loginURL     string
	loginStarted time.Time
}

func New(upstream Upstream, account Account, cfg settings.Config, keys settings.Keys, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	readTimeout := 3*cfg.UnaryTimeout + 20*time.Second
	if cfg.UnaryTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}
	return &Server{
		upstream: upstream, account: account, cfg: cfg, keys: keys, log: logger,
		sessionID: SessionID(), cacheHistory: newHistory(),
		bodies: make(chan struct{}, cfg.MaxInFlight+8), slots: make(chan struct{}, cfg.MaxInFlight),
		now: time.Now, modelUntil: make(map[string]time.Time),
		models: cache[[]aicode.Model]{ttl: cfg.CatalogTTL, timeout: readTimeout, load: func(ctx context.Context) ([]aicode.Model, error) {
			response, err := upstream.FetchConfig(ctx)
			if err != nil {
				return nil, err
			}
			return aicode.Models(response), nil
		}},
		quota: cache[[]aicode.QuotaBucket]{ttl: cfg.QuotaTTL, timeout: readTimeout, load: func(ctx context.Context) ([]aicode.QuotaBucket, error) {
			response, err := upstream.FetchQuota(ctx)
			if err != nil {
				return nil, err
			}
			return aicode.Quota(response), nil
		}},
	}
}

// The IDE uses its UsageTracker for this label. A standalone process uses the
// plugin's fallback strategy: one local UUID for the process, not a resume token.
func SessionID() string {
	var id [16]byte
	rand.Read(id[:])
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}

type apiError struct {
	status               int
	code, message, param string
	retry                time.Duration
	upstream             *aicode.Error
}

func bad(status int, code, msg, param string) *apiError {
	return &apiError{status: status, code: code, message: msg, param: param}
}

func apiFailure(err error) *apiError {
	var bridge *chat.Error
	if errors.As(err, &bridge) {
		return bad(bridge.Status, bridge.Code, bridge.Message, bridge.Param)
	}
	var credential *auth.Error
	if errors.As(err, &credential) {
		e := bad(http.StatusServiceUnavailable, "upstream_auth_error", "The Google credential could not be loaded or refreshed.", "")
		switch credential.Code {
		case "oauth_client_not_configured":
			e.code, e.message = "upstream_auth_required", "Configure the deployment's OAuth client before authorizing it."
		case "restricted_client", "invalid_client", "unauthorized_client", "invalid_scope", "redirect_uri_mismatch":
			e.code, e.message = "upstream_oauth_client_rejected", "Google rejected this deployment's OAuth client configuration."
		case "not_logged_in", "reauth_required", "invalid_grant", "missing_refresh_token", "missing_scope":
			e.code, e.message = "upstream_auth_required", "Google authorization is required; run asgemini2api login."
		case "transient_error", "transient_cooldown", "network_error":
			e.code, e.message = "upstream_auth_unavailable", "Google token refresh is temporarily unavailable."
		}
		e.retry = credential.RetryAfter
		return e
	}
	var rpc *aicode.Error
	if errors.As(err, &rpc) {
		status, code, msg := http.StatusBadGateway, "upstream_error", "The upstream gRPC request failed."
		switch rpc.Code {
		case codes.Unauthenticated:
			status, code, msg = http.StatusUnauthorized, "upstream_unauthenticated", "The upstream rejected Google authorization."
		case codes.PermissionDenied:
			status, code, msg = http.StatusForbidden, "upstream_permission_denied", "The upstream denied this request."
		case codes.ResourceExhausted:
			status, code, msg = http.StatusTooManyRequests, "upstream_quota_exhausted", "The upstream returned a quota or rate limit error."
		case codes.DeadlineExceeded:
			status, code, msg = http.StatusGatewayTimeout, "upstream_deadline_exceeded", "The upstream deadline expired."
		case codes.Unavailable:
			status, code, msg = http.StatusServiceUnavailable, "upstream_unavailable", "The upstream is temporarily unavailable."
		case codes.InvalidArgument:
			status, code, msg = http.StatusBadRequest, "upstream_invalid_argument", "The upstream rejected the request fields."
		}
		return &apiError{status: status, code: code, message: msg, upstream: rpc, retry: rpc.RetryAfter}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return bad(http.StatusGatewayTimeout, "deadline_exceeded", "The request deadline expired.", "")
	}
	return bad(http.StatusInternalServerError, "internal_error", "An internal proxy error occurred.", "")
}

func secondsCeil(d time.Duration) int64 {
	return int64((d + time.Second - 1) / time.Second)
}

func (e *apiError) body() map[string]any {
	errorType := "invalid_request_error"
	switch {
	case e.status == http.StatusUnauthorized:
		errorType = "authentication_error"
	case e.status == http.StatusTooManyRequests:
		errorType = "rate_limit_error"
	case e.status >= 500:
		errorType = "server_error"
	}
	var param any
	if e.param != "" {
		param = e.param
	}
	fields := map[string]any{"message": e.message, "type": errorType, "code": e.code, "param": param}
	if u := e.upstream; u != nil {
		meta := map[string]string{"rpc": u.RPC, "status": u.Code.String()}
		if u.Reason != "" {
			meta["reason"] = u.Reason
		}
		if u.Domain != "" {
			meta["domain"] = u.Domain
		}
		fields["upstream"] = meta
	}
	if e.retry > 0 {
		fields["retry_after"] = secondsCeil(e.retry)
	}
	return map[string]any{"error": fields}
}

func writeJSON(w http.ResponseWriter, status int, body any) error {
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(15 * time.Second))
	defer controller.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(body)
}

func (s *Server) logError(event, requestID string, e *apiError) {
	attrs := []any{"request_id", requestID, "code", e.code, "http_status", e.status}
	if u := e.upstream; u != nil {
		attrs = append(attrs, "rpc", u.RPC, "grpc_status", u.Code.String())
	}
	s.log.Warn(event, attrs...)
}

func (s *Server) fail(w http.ResponseWriter, id string, e *apiError) {
	s.logError("request_error", id, e)
	if e.retry > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(secondsCeil(e.retry), 10))
	}
	if e.code == "invalid_api_key" {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	writeJSON(w, e.status, e.body())
}

func authorized(r *http.Request, expected [sha256.Size]byte) bool {
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return false
	}
	scheme, secret, ok := strings.Cut(headers[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || len(secret) < 24 || len(secret) > 1024 {
		return false
	}
	provided := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(expected[:], provided[:]) == 1
}

type endpoint func(http.ResponseWriter, *http.Request, string)

func (s *Server) route(key *[sha256.Size]byte, handler endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := rand.Text()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Request-Id", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if key != nil && !authorized(r, *key) {
			s.fail(w, id, bad(http.StatusUnauthorized, "invalid_api_key", "A valid Bearer API key is required.", ""))
			return
		}
		handler(w, r, id)
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.route(nil, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))
	mux.HandleFunc("GET /readyz", s.route(nil, s.ready))
	mux.HandleFunc("GET /v1/models", s.route(&s.keys.API, s.listModels))
	mux.HandleFunc("GET /v1/models/{id...}", s.route(&s.keys.API, s.listModels))
	mux.HandleFunc("POST /v1/chat/completions", s.route(&s.keys.API, s.complete))
	mux.HandleFunc("GET /admin/oauth", s.route(nil, s.oauthConsole))
	mux.HandleFunc("POST /admin/oauth/start", s.route(&s.keys.Admin, s.startOAuth))
	mux.HandleFunc("POST /admin/oauth/complete", s.route(&s.keys.Admin, s.completeOAuth))
	mux.HandleFunc("GET /admin/account", s.route(&s.keys.Admin, s.getAccount))
	mux.HandleFunc("GET /admin/models", s.route(&s.keys.Admin, s.getModels))
	mux.HandleFunc("GET /admin/quota", s.route(&s.keys.Admin, s.getQuota))
	return mux
}

func (s *Server) ready(w http.ResponseWriter, _ *http.Request, _ string) {
	state, err := s.account.Status()
	if err != nil || !state.LoggedIn || state.ReauthRequired || state.ClientConfigError != "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

type openAIModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

func (s *Server) listModels(w http.ResponseWriter, r *http.Request, id string) {
	state, err := s.models.get(r.Context(), false)
	if err != nil {
		s.handleFailure(w, r, id, err)
		return
	}
	lookup := r.PathValue("id")
	list := make([]openAIModel, 0, len(state.Value))
	for _, m := range state.Value {
		model := openAIModel{ID: m.ID, Object: "model", OwnedBy: "google"}
		if lookup == m.ID {
			writeJSON(w, http.StatusOK, model)
			return
		}
		list = append(list, model)
	}
	if lookup != "" {
		s.fail(w, id, bad(http.StatusNotFound, "model_not_found", "This model is not available for the active account.", "model"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": list})
}

func (s *Server) getModels(w http.ResponseWriter, r *http.Request, id string) {
	state, err := s.models.get(r.Context(), r.URL.Query().Get("refresh") == "true")
	if err != nil {
		s.handleFailure(w, r, id, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fetched_at": state.FetchedAt, "models": state.Value})
}

func (s *Server) getQuota(w http.ResponseWriter, r *http.Request, id string) {
	state, err := s.quota.get(r.Context(), r.URL.Query().Get("refresh") == "true")
	if err != nil {
		s.handleFailure(w, r, id, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fetched_at": state.FetchedAt, "buckets": state.Value})
}

func (s *Server) getAccount(w http.ResponseWriter, r *http.Request, id string) {
	state, err := s.account.Status()
	if err != nil {
		s.handleFailure(w, r, id, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleFailure(w http.ResponseWriter, r *http.Request, id string, err error) {
	if r.Context().Err() != nil {
		s.log.Info("request_cancelled", "request_id", id)
		return
	}
	s.fail(w, id, apiFailure(err))
}

func decodeBody(w http.ResponseWriter, r *http.Request, limit int64) (*chat.Request, *apiError) {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		media, _, err := mime.ParseMediaType(ct)
		if err != nil || media != "application/json" {
			return nil, bad(http.StatusUnsupportedMediaType, "invalid_content_type", "Content-Type must be application/json.", "")
		}
	}
	tooLarge := bad(http.StatusRequestEntityTooLarge, "request_too_large", "The request body is too large.", "")
	if r.ContentLength > limit {
		return nil, tooLarge
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			return nil, tooLarge
		}
		return nil, bad(http.StatusBadRequest, "invalid_request_error", "The request body could not be read.", "")
	}
	req, err := chat.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, apiFailure(err)
	}
	if req.Model == "" || len(req.Model) > 256 {
		return nil, bad(http.StatusBadRequest, "invalid_request_error", "A model ID from /v1/models is required.", "model")
	}
	if len(req.Messages) == 0 || len(req.Messages) > 1024 {
		return nil, bad(http.StatusBadRequest, "invalid_request_error", "messages must contain 1–1024 items.", "messages")
	}
	return req, nil
}

func (s *Server) cooldown(model string) *apiError {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if remaining := s.globalUntil.Sub(now); remaining > 0 {
		return &apiError{status: 503, code: "upstream_cooldown", message: "The upstream is temporarily unavailable.", retry: remaining}
	}
	for id, until := range s.modelUntil {
		if !until.After(now) {
			delete(s.modelUntil, id)
		}
	}
	if until, ok := s.modelUntil[model]; ok {
		return &apiError{status: 429, code: "upstream_quota_exhausted", message: "This model is cooling down after an upstream quota error.", retry: until.Sub(now)}
	}
	return nil
}

func (s *Server) recordCooldown(model string, failure *apiError) {
	u := failure.upstream
	if u == nil {
		return
	}
	now := time.Now()
	delay := u.RetryAfter
	if u.Code == codes.ResourceExhausted && delay == 0 {
		delay = 30 * time.Second
		state := s.quota.latest()
		if now.Sub(state.FetchedAt) < s.cfg.QuotaTTL {
			for _, bucket := range state.Value {
				if bucket.ModelID == model && bucket.RemainingFraction != nil && *bucket.RemainingFraction == 0 && bucket.ResetTime != nil {
					delay = max(delay, min(bucket.ResetTime.Sub(now), 7*24*time.Hour))
				}
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch u.Code {
	case codes.ResourceExhausted:
		until := now.Add(delay)
		if until.After(s.modelUntil[model]) {
			s.modelUntil[model] = until
		}
		failure.retry = s.modelUntil[model].Sub(now)
	case codes.Unavailable:
		if delay == 0 {
			delay = 2 * time.Second
		}
		if until := now.Add(delay); until.After(s.globalUntil) {
			s.globalUntil = until
		}
		failure.retry = s.globalUntil.Sub(now)
	}
}

func busy() *apiError {
	return &apiError{status: 429, code: "proxy_busy", message: "The proxy reached its concurrent request limit.", retry: time.Second}
}

func (s *Server) complete(w http.ResponseWriter, r *http.Request, id string) {
	select {
	case s.bodies <- struct{}{}:
		defer func() { <-s.bodies }()
	default:
		s.fail(w, id, busy())
		return
	}
	req, failure := decodeBody(w, r, s.cfg.MaxBodyBytes)
	if failure != nil {
		s.fail(w, id, failure)
		return
	}
	conversation := r.Header.Get("X-Studio-Conversation-Id")
	if len(conversation) > 256 || len(req.User) > 256 {
		s.fail(w, id, bad(http.StatusBadRequest, "invalid_request_error", "Invalid conversation partition.", ""))
		return
	}
	models, err := s.models.get(r.Context(), false)
	if err != nil {
		s.handleFailure(w, r, id, err)
		return
	}
	var model *aicode.Model
	for _, candidate := range models.Value {
		if candidate.ID == req.Model {
			model = &candidate
			break
		}
	}
	if model == nil {
		s.fail(w, id, bad(http.StatusNotFound, "model_not_found", "This model is not available for the active account.", "model"))
		return
	}
	if denied := s.cooldown(model.ID); denied != nil {
		s.fail(w, id, denied)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.fail(w, id, busy())
		return
	}
	history := s.cacheHistory.view(model.ID, model.Experience, req.User, conversation, req.Messages)
	payload, err := chat.Encode(req, *model, s.sessionID, history.restore)
	if err != nil {
		s.handleFailure(w, r, id, err)
		return
	}
	if r.Context().Err() != nil {
		return
	}
	if denied := s.cooldown(model.ID); denied != nil {
		s.fail(w, id, denied)
		return
	}
	completion := chat.NewCompletion(model.ID, req.StreamOptions != nil && req.StreamOptions.IncludeUsage)
	stream := &sse{w: w}
	var size int
	err = s.upstream.Stream(r.Context(), payload, func(response *pb.GenerateContentResponse) error {
		size += proto.Size(response)
		if size > maxReplyBytes {
			return &chat.Error{Status: 502, Code: "upstream_response_too_large", Message: "The upstream response exceeded the proxy limit."}
		}
		chunks, err := completion.Push(response)
		if err != nil || !req.Stream {
			return err
		}
		return stream.chunks(chunks)
	})
	var result chat.Result
	if err == nil {
		if req.Stream {
			var chunks []chat.Chunk
			chunks, err = completion.Finish()
			if err == nil {
				err = stream.chunks(chunks)
			}
		} else {
			result, err = completion.Result()
		}
	}
	if err != nil {
		failure := apiFailure(err)
		s.recordCooldown(model.ID, failure)
		if r.Context().Err() != nil || stream.failed {
			s.log.Info("generation_cancelled", "request_id", id)
		} else if stream.started {
			s.logError("stream_interrupted", id, failure)
			_ = stream.event(failure.body())
		} else {
			s.fail(w, id, failure)
		}
		return
	}
	if msg, content, ok := completion.History(); ok {
		history.remember(msg, content)
	}
	if req.Stream {
		if err := stream.done(); err != nil {
			s.log.Info("generation_cancelled", "request_id", id)
			return
		}
	} else if err := writeJSON(w, http.StatusOK, result); err != nil {
		s.log.Info("generation_cancelled", "request_id", id)
		return
	}
	s.log.Info("generation_finished", "request_id", id, "stream", req.Stream)
}

type sse struct {
	w       http.ResponseWriter
	started bool
	failed  bool
}

func (s *sse) write(data []byte) error {
	controller := http.NewResponseController(s.w)
	_ = controller.SetWriteDeadline(time.Now().Add(15 * time.Second))
	defer controller.SetWriteDeadline(time.Time{})
	if !s.started {
		s.w.Header().Set("Content-Type", "text/event-stream")
		s.w.Header().Set("X-Accel-Buffering", "no")
		s.w.WriteHeader(http.StatusOK)
		s.started = true
	}
	_, err := s.w.Write(append(append([]byte("data: "), data...), '\n', '\n'))
	if err == nil {
		err = controller.Flush()
	}
	if err != nil {
		s.failed = true
	}
	return err
}

func (s *sse) event(item any) error {
	blob, err := json.Marshal(item)
	if err != nil {
		return err
	}
	return s.write(blob)
}

func (s *sse) chunks(chunks []chat.Chunk) error {
	for _, chunk := range chunks {
		if err := s.event(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *sse) done() error { return s.write([]byte("[DONE]")) }
