package aicode

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/ayatinene/ASGemini2API/internal/aicode/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	// DefaultTarget is the production AiCode gRPC endpoint.
	DefaultTarget = "aicode.googleapis.com:443"
	// DefaultUnaryTimeout is the default timeout applied to unary RPCs.
	DefaultUnaryTimeout = 30 * time.Second
	// DefaultStreamTimeout is the default timeout applied to streaming generation RPCs.
	DefaultStreamTimeout = 300 * time.Second

	defaultMaxReceiveBytes = 16 * 1024 * 1024
	defaultRetryBackoff    = 50 * time.Millisecond
	maxReplacedHistory     = 16

	userAgentProduct      = "ASGemini2API"
	userAgentVersion      = "dev"
	clientIdentityComment = "headless"

	rpcFetchConfig    = "google.gca.aicode.v1.ManagementService/FetchConfig"
	rpcFetchQuota     = "google.gca.aicode.v1.PredictionService/FetchQuotaStatus"
	rpcStreamGenerate = "google.gca.aicode.v1.PredictionService/StreamGenerateContent"
)

// TokenProvider supplies OAuth2 bearer access tokens and handles rejected-token refresh.
type TokenProvider interface {
	AccessToken(ctx context.Context, rejected string) (string, error)
}

// Options configures the AiCode gRPC client.
type Options struct {
	UnaryTimeout  time.Duration
	StreamTimeout time.Duration

	// Package-internal test hooks (not exported outside package aicode).
	target          string
	tlsConfig       *tls.Config
	dialOptions     []grpc.DialOption
	retryBackoff    time.Duration
	retryBackoffSet bool
	noTLSForTest    bool
}

// ProbeResult describes the sanitized result of an unauthenticated endpoint/TLS probe.
type ProbeResult struct {
	Endpoint        string        `json:"endpoint"`
	UserAgent       string        `json:"user_agent"`
	RPC             string        `json:"rpc"`
	ReachedEndpoint bool          `json:"reached_endpoint"`
	Code            codes.Code    `json:"code"`
	Reason          string        `json:"reason,omitempty"`
	Domain          string        `json:"domain,omitempty"`
	RetryAfter      time.Duration `json:"retry_after,omitempty"`
	Guidance        string        `json:"guidance"`
}

// Client is an async-safe gRPC client for the private AiCode service.
type Client struct {
	tokens        TokenProvider
	conn          *grpc.ClientConn
	management    pb.ManagementServiceClient
	prediction    pb.PredictionServiceClient
	target        string
	userAgent     string
	unaryTimeout  time.Duration
	streamTimeout time.Duration
	retryBackoff  time.Duration

	closed atomic.Bool

	tokenMu        sync.Mutex
	rejectedToken  string
	replacedTokens []string
	refreshSem     chan struct{}
}

// New constructs a Client connected to the AiCode gRPC service over TLS 1.2+.
func New(tokens TokenProvider, options Options) (*Client, error) {
	unaryTimeout := options.UnaryTimeout
	if unaryTimeout == 0 {
		unaryTimeout = DefaultUnaryTimeout
	} else if unaryTimeout < 0 {
		return nil, fmt.Errorf("aicode: UnaryTimeout must be positive, got %s", unaryTimeout)
	}

	streamTimeout := options.StreamTimeout
	if streamTimeout == 0 {
		streamTimeout = DefaultStreamTimeout
	} else if streamTimeout < 0 {
		return nil, fmt.Errorf("aicode: StreamTimeout must be positive, got %s", streamTimeout)
	}

	retryBackoff := defaultRetryBackoff
	if options.retryBackoffSet {
		if options.retryBackoff < 0 {
			return nil, fmt.Errorf("aicode: retryBackoff must be non-negative")
		}
		retryBackoff = options.retryBackoff
	}

	target := DefaultTarget
	if options.target != "" {
		target = options.target
	}

	ua := buildUserAgent()
	dialOpts := []grpc.DialOption{
		grpc.WithUserAgent(ua),
		grpc.WithDisableRetry(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(defaultMaxReceiveBytes)),
	}

	if options.noTLSForTest {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		var tlsCfg *tls.Config
		if options.tlsConfig != nil {
			tlsCfg = options.tlsConfig.Clone()
		} else {
			tlsCfg = &tls.Config{}
		}
		if tlsCfg.MinVersion < tls.VersionTLS12 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
		if tlsCfg.ServerName == "" && !tlsCfg.InsecureSkipVerify {
			if host, _, err := net.SplitHostPort(target); err == nil && host != "" {
				tlsCfg.ServerName = host
			}
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}

	if len(options.dialOptions) > 0 {
		dialOpts = append(dialOpts, options.dialOptions...)
	}

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("aicode: failed to create gRPC client: %w", err)
	}

	return &Client{
		tokens:        tokens,
		conn:          conn,
		management:    pb.NewManagementServiceClient(conn),
		prediction:    pb.NewPredictionServiceClient(conn),
		target:        target,
		userAgent:     ua,
		unaryTimeout:  unaryTimeout,
		streamTimeout: streamTimeout,
		retryBackoff:  retryBackoff,
		refreshSem:    make(chan struct{}, 1),
	}, nil
}

// Target returns the configured gRPC target endpoint.
func (c *Client) Target() string {
	return c.target
}

// UserAgent returns the application User-Agent prefix sent on gRPC calls.
func (c *Client) UserAgent() string {
	return c.userAgent
}

// Close closes the underlying gRPC client connection. It is idempotent.
func (c *Client) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// FetchConfig calls ManagementService/FetchConfig with bounded unary retry and rejected-token refresh.
func (c *Client) FetchConfig(ctx context.Context) (*pb.FetchConfigResponse, error) {
	return doUnary(c, ctx, rpcFetchConfig, func(callCtx context.Context, trailer *metadata.MD) (*pb.FetchConfigResponse, error) {
		return c.management.FetchConfig(callCtx, &pb.FetchConfigRequest{}, grpc.Trailer(trailer))
	})
}

// FetchQuota calls PredictionService/FetchQuotaStatus with bounded unary retry and rejected-token refresh.
func (c *Client) FetchQuota(ctx context.Context) (*pb.FetchQuotaStatusResponse, error) {
	return doUnary(c, ctx, rpcFetchQuota, func(callCtx context.Context, trailer *metadata.MD) (*pb.FetchQuotaStatusResponse, error) {
		return c.prediction.FetchQuotaStatus(callCtx, &pb.FetchQuotaStatusRequest{}, grpc.Trailer(trailer))
	})
}

// Stream calls PredictionService/StreamGenerateContent with no retries and cancels the underlying stream on exit.
func (c *Client) Stream(ctx context.Context, req *pb.GenerateContentRequest, yield func(*pb.GenerateContentResponse) error) error {
	if c.closed.Load() {
		return &Error{
			Code:     codes.Canceled,
			RPC:      rpcStreamGenerate,
			Reason:   "CLIENT_CLOSED",
			Guidance: "AiCode client has already been closed.",
		}
	}
	if req == nil {
		return &Error{
			Code:     codes.InvalidArgument,
			RPC:      rpcStreamGenerate,
			Reason:   "REQUEST_NIL",
			Guidance: "GenerateContentRequest must not be nil.",
		}
	}
	if yield == nil {
		return &Error{
			Code:     codes.InvalidArgument,
			RPC:      rpcStreamGenerate,
			Reason:   "YIELD_NIL",
			Guidance: "Stream yield callback must not be nil.",
		}
	}

	token, err := c.fetchBearerToken(ctx, rpcStreamGenerate, "")
	if err != nil {
		return err
	}

	callCtx, cancel := withBoundedTimeout(ctx, c.streamTimeout)
	defer cancel()
	callCtx = metadata.NewOutgoingContext(callCtx, metadata.Pairs("authorization", "Bearer "+token))

	// Commit as soon as the request is buffered; unlike read-only RPCs, a
	// generation must not buffer its protobuf body for a transport replay.
	stream, err := c.prediction.StreamGenerateContent(callCtx, req, grpc.MaxRetryRPCBufferSize(0))
	if err != nil {
		rpcErr := parseRPCError(err, rpcStreamGenerate, nil)
		if tokenExpired(rpcErr) {
			c.recordRejectedToken(token)
		}
		return rpcErr
	}

	for {
		resp, recvErr := stream.Recv()
		if recvErr == io.EOF {
			return nil
		}
		if recvErr != nil {
			rpcErr := parseRPCError(recvErr, rpcStreamGenerate, stream.Trailer())
			if tokenExpired(rpcErr) {
				c.recordRejectedToken(token)
			}
			return rpcErr
		}
		if yieldErr := yield(resp); yieldErr != nil {
			return yieldErr
		}
	}
}

// Probe performs an unauthenticated FetchConfig call to verify TLS and endpoint reachability.
func (c *Client) Probe(ctx context.Context) (ProbeResult, error) {
	if c.closed.Load() {
		err := &Error{
			Code:     codes.Canceled,
			RPC:      rpcFetchConfig,
			Reason:   "CLIENT_CLOSED",
			Guidance: "AiCode client has already been closed.",
		}
		return ProbeResult{
			Endpoint:        c.target,
			UserAgent:       c.userAgent,
			RPC:             rpcFetchConfig,
			ReachedEndpoint: false,
			Code:            err.Code,
			Reason:          err.Reason,
			Guidance:        err.Guidance,
		}, err
	}

	callCtx, cancel := withBoundedTimeout(ctx, c.unaryTimeout)
	defer cancel()
	callCtx = metadata.NewOutgoingContext(callCtx, metadata.MD{})

	var header, trailer metadata.MD
	_, err := c.management.FetchConfig(callCtx, &pb.FetchConfigRequest{}, grpc.Header(&header), grpc.Trailer(&trailer))
	if err == nil {
		return ProbeResult{
			Endpoint:        c.target,
			UserAgent:       c.userAgent,
			RPC:             rpcFetchConfig,
			ReachedEndpoint: true,
			Code:            codes.OK,
			Guidance:        statusGuidance(codes.OK),
		}, nil
	}

	rpcErr := parseRPCError(err, rpcFetchConfig, trailer)
	reached := ctx.Err() == nil && (len(header) != 0 || len(trailer) != 0 || rpcErr.Reason != "" || rpcErr.Domain != "" ||
		(rpcErr.Code != codes.Unavailable && rpcErr.Code != codes.DeadlineExceeded && rpcErr.Code != codes.Canceled && rpcErr.Code != codes.Unknown))

	res := ProbeResult{
		Endpoint:        c.target,
		UserAgent:       c.userAgent,
		RPC:             rpcFetchConfig,
		ReachedEndpoint: reached,
		Code:            rpcErr.Code,
		Reason:          rpcErr.Reason,
		Domain:          rpcErr.Domain,
		RetryAfter:      rpcErr.RetryAfter,
		Guidance:        rpcErr.Guidance,
	}
	if !reached {
		return res, rpcErr
	}
	return res, nil
}

func doUnary[T any](
	c *Client,
	ctx context.Context,
	rpcName string,
	invoke func(callCtx context.Context, trailer *metadata.MD) (T, error),
) (T, error) {
	var zero T
	if c.closed.Load() {
		return zero, &Error{
			Code:     codes.Canceled,
			RPC:      rpcName,
			Reason:   "CLIENT_CLOSED",
			Guidance: "AiCode client has already been closed.",
		}
	}

	refreshed := false
	transientRetried := false
	rejectedForAttempt := ""

	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return zero, parseRPCError(ctxErr, rpcName, nil)
		}

		token, err := c.fetchBearerToken(ctx, rpcName, rejectedForAttempt)
		if err != nil {
			return zero, err
		}
		rejectedForAttempt = ""

		attemptCtx, cancel := withBoundedTimeout(ctx, c.unaryTimeout)
		attemptCtx = metadata.NewOutgoingContext(attemptCtx, metadata.Pairs("authorization", "Bearer "+token))

		var trailer metadata.MD
		resp, callErr := invoke(attemptCtx, &trailer)
		cancel()

		if callErr == nil {
			return resp, nil
		}

		rpcErr := parseRPCError(callErr, rpcName, trailer)
		if tokenExpired(rpcErr) {
			c.recordRejectedToken(token)
			if !refreshed && ctx.Err() == nil {
				refreshed = true
				rejectedForAttempt = token
				continue
			}
		}
		if isSafeUnaryRetryCode(rpcErr.Code) && rpcErr.RetryAfter == 0 && !transientRetried && ctx.Err() == nil {
			transientRetried = true
			if c.retryBackoff > 0 {
				timer := time.NewTimer(c.retryBackoff)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return zero, parseRPCError(ctx.Err(), rpcName, nil)
				}
			}
			continue
		}
		return zero, rpcErr
	}
}

// Only an explicit expiry signal justifies a new token. Admission, scope and
// account errors cannot be fixed by repeatedly refreshing the same grant.
func tokenExpired(err *Error) bool {
	return err.Code == codes.Unauthenticated && err.Domain == "googleapis.com" && err.Reason == "ACCESS_TOKEN_EXPIRED"
}

func isSafeUnaryRetryCode(code codes.Code) bool {
	return code == codes.Unavailable || code == codes.DeadlineExceeded
}

func (c *Client) recordRejectedToken(token string) {
	if token == "" {
		return
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if slices.Contains(c.replacedTokens, token) {
		return
	}
	c.rejectedToken = token
}

func (c *Client) peekRejectedToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	return c.rejectedToken
}

func (c *Client) completeTokenFetch(usedRejected, newToken string) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if idx := slices.Index(c.replacedTokens, newToken); idx >= 0 {
		c.replacedTokens = slices.Delete(c.replacedTokens, idx, idx+1)
	}
	if usedRejected != "" {
		if newToken != usedRejected && !slices.Contains(c.replacedTokens, usedRejected) {
			if len(c.replacedTokens) >= maxReplacedHistory {
				c.replacedTokens = append(c.replacedTokens[1:], usedRejected)
			} else {
				c.replacedTokens = append(c.replacedTokens, usedRejected)
			}
		}
		if c.rejectedToken == usedRejected {
			c.rejectedToken = ""
		}
	}
}

func (c *Client) fetchBearerToken(ctx context.Context, rpcName, explicitRejected string) (string, error) {
	if c.tokens == nil {
		return "", &Error{
			Code:     codes.Unauthenticated,
			RPC:      rpcName,
			Reason:   "TOKEN_PROVIDER_MISSING",
			Guidance: "No token provider configured for authenticated AiCode RPC.",
		}
	}

	effectiveRejected := explicitRejected
	if effectiveRejected == "" {
		effectiveRejected = c.peekRejectedToken()
	}

	if effectiveRejected == "" {
		tok, err := c.tokens.AccessToken(ctx, "")
		if err != nil {
			return "", err
		}
		validated, valErr := validateBearerToken(tok, rpcName)
		if valErr != nil {
			return "", valErr
		}
		c.completeTokenFetch("", validated)
		return validated, nil
	}

	select {
	case c.refreshSem <- struct{}{}:
		defer func() { <-c.refreshSem }()
	case <-ctx.Done():
		return "", parseRPCError(ctx.Err(), rpcName, nil)
	}

	effectiveRejected = explicitRejected
	if effectiveRejected == "" {
		effectiveRejected = c.peekRejectedToken()
	}

	tok, err := c.tokens.AccessToken(ctx, effectiveRejected)
	if err != nil {
		return "", err
	}
	validated, valErr := validateBearerToken(tok, rpcName)
	if valErr != nil {
		return "", valErr
	}
	c.completeTokenFetch(effectiveRejected, validated)
	return validated, nil
}

func validateBearerToken(token, rpcName string) (string, error) {
	if token == "" {
		return "", &Error{
			Code:     codes.Unauthenticated,
			RPC:      rpcName,
			Reason:   "TOKEN_EMPTY",
			Guidance: "Token provider returned an empty OAuth access token.",
		}
	}
	for i := 0; i < len(token); i++ {
		b := token[i]
		if b < 33 || b > 126 {
			return "", &Error{
				Code:     codes.Unauthenticated,
				RPC:      rpcName,
				Reason:   "TOKEN_INVALID",
				Guidance: "Token provider returned an invalid OAuth access token.",
			}
		}
	}
	return token, nil
}

func withBoundedTimeout(ctx context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	if limit <= 0 {
		return context.WithCancel(ctx)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if time.Until(deadline) <= limit {
			return context.WithCancel(ctx)
		}
	}
	return context.WithTimeout(ctx, limit)
}

func buildUserAgent() string {
	osType, osVersion, arch := hostOSDetails()
	return buildUserAgentWith(userAgentProduct, userAgentVersion, clientIdentityComment, osType, osVersion, arch)
}

func buildUserAgentWith(product, version, identity, osType, osVersion, arch string) string {
	cleanProduct := sanitizeAlnum(product, userAgentProduct)
	cleanVersion := sanitizeTokenSegment(version, userAgentVersion)
	cleanIdentity := sanitizeTokenSegment(identity, clientIdentityComment)
	cleanOSType := sanitizeTokenSegment(osType, "Linux")
	cleanOSVersion := sanitizeTokenSegment(osVersion, "unknown")
	cleanArch := sanitizeTokenSegment(arch, "aarch64")
	return fmt.Sprintf(
		"%s/%s (%s; os_type=%s; os_version=%s; arch=%s)",
		cleanProduct,
		cleanVersion,
		cleanIdentity,
		cleanOSType,
		cleanOSVersion,
		cleanArch,
	)
}

func sanitizeAlnum(s, fallback string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return fallback
	}
	return b.String()
}

func sanitizeTokenSegment(s, fallback string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return fallback
	}
	return b.String()
}
