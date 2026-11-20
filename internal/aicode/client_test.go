package aicode

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/aicode/pb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

type stubTokenProvider struct {
	mu     sync.Mutex
	tokens []string
	err    error
	calls  []string
}

func (s *stubTokenProvider) AccessToken(_ context.Context, rejected string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, rejected)
	if s.err != nil {
		return "", s.err
	}
	if rejected != "" && len(s.tokens) > 1 {
		return s.tokens[1], nil
	}
	if len(s.tokens) == 0 {
		return "", nil
	}
	return s.tokens[0], nil
}

func (s *stubTokenProvider) recordedCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.calls))
	copy(out, s.calls)
	return out
}

type fakeServers struct {
	pb.UnimplementedManagementServiceServer
	pb.UnimplementedPredictionServiceServer

	onFetchConfig func(context.Context, *pb.FetchConfigRequest) (*pb.FetchConfigResponse, error)
	onFetchQuota  func(context.Context, *pb.FetchQuotaStatusRequest) (*pb.FetchQuotaStatusResponse, error)
	onStream      func(*pb.GenerateContentRequest, grpc.ServerStreamingServer[pb.GenerateContentResponse]) error
}

func (f *fakeServers) FetchConfig(ctx context.Context, req *pb.FetchConfigRequest) (*pb.FetchConfigResponse, error) {
	return f.onFetchConfig(ctx, req)
}

func (f *fakeServers) FetchQuotaStatus(ctx context.Context, req *pb.FetchQuotaStatusRequest) (*pb.FetchQuotaStatusResponse, error) {
	return f.onFetchQuota(ctx, req)
}

func (f *fakeServers) StreamGenerateContent(req *pb.GenerateContentRequest, srv grpc.ServerStreamingServer[pb.GenerateContentResponse]) error {
	return f.onStream(req, srv)
}

func generateTestTLS(t *testing.T, dnsName string) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	cert := tls.Certificate{
		Certificate: [][]byte{srvDER},
		PrivateKey:  srvKey,
	}
	return pool, cert
}

func startFakeTLSServer(t *testing.T, srvCert tls.Certificate, fake *fakeServers, tlsMutate func(*tls.Config)) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		MinVersion:   tls.VersionTLS12,
	}
	if tlsMutate != nil {
		tlsMutate(tlsCfg)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	pb.RegisterManagementServiceServer(gs, fake)
	pb.RegisterPredictionServiceServer(gs, fake)

	go func() {
		_ = gs.Serve(lis)
	}()

	_, port, _ := net.SplitHostPort(lis.Addr().String())
	target := net.JoinHostPort("localhost", port)
	cleanup := func() {
		gs.Stop()
		_ = lis.Close()
	}
	return target, cleanup
}

func TestDefaultsAndUserAgent(t *testing.T) {
	if DefaultTarget != "aicode.googleapis.com:443" {
		t.Fatalf("unexpected DefaultTarget: %s", DefaultTarget)
	}
	c, err := New(nil, Options{})
	if err != nil {
		t.Fatalf("New(nil, Options{}) failed: %v", err)
	}
	defer c.Close()

	if c.Target() != DefaultTarget {
		t.Fatalf("expected target %s, got %s", DefaultTarget, c.Target())
	}
	ua := c.UserAgent()
	if !strings.HasPrefix(ua, "ASGemini2API/dev (headless; ") {
		t.Fatalf("unexpected UserAgent prefix: %q", ua)
	}
	if runtime.GOOS == "linux" {
		if !strings.Contains(ua, "os_type=Linux;") {
			t.Fatalf("expected Linux os_type in UA: %q", ua)
		}
		if runtime.GOARCH == "arm64" && !strings.Contains(ua, "arch=aarch64)") {
			t.Fatalf("expected native Linux arm64 arch=aarch64 in UA: %q", ua)
		}
	}

	if _, err := New(nil, Options{UnaryTimeout: -time.Second}); err == nil {
		t.Fatal("expected error for negative UnaryTimeout")
	}
	if _, err := New(nil, Options{StreamTimeout: -time.Second}); err == nil {
		t.Fatal("expected error for negative StreamTimeout")
	}
}

func TestTLS12AndCertVerification(t *testing.T) {
	pool, srvCert := generateTestTLS(t, "localhost")

	var mu sync.Mutex
	var captured []metadata.MD
	streamCancelled := make(chan struct{})

	fake := &fakeServers{
		onFetchConfig: func(ctx context.Context, _ *pb.FetchConfigRequest) (*pb.FetchConfigResponse, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			mu.Lock()
			captured = append(captured, md)
			mu.Unlock()
			return &pb.FetchConfigResponse{
				AvailableExperiences: []*pb.FetchConfigResponse_Experience{
					{
						Name:  "chat_agent_mode/synth",
						Model: &pb.FetchConfigResponse_Model{ModelId: "synth-1"},
					},
				},
			}, nil
		},
		onFetchQuota: func(ctx context.Context, _ *pb.FetchQuotaStatusRequest) (*pb.FetchQuotaStatusResponse, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			mu.Lock()
			captured = append(captured, md)
			mu.Unlock()
			return &pb.FetchQuotaStatusResponse{
				Buckets: []*pb.FetchQuotaStatusResponse_BucketInfo{
					{
						RemainingFraction: 0.5,
						Model:             &pb.Model{ModelId: "synth-1"},
					},
				},
			}, nil
		},
		onStream: func(req *pb.GenerateContentRequest, srv grpc.ServerStreamingServer[pb.GenerateContentResponse]) error {
			md, _ := metadata.FromIncomingContext(srv.Context())
			mu.Lock()
			captured = append(captured, md)
			mu.Unlock()
			for i := 0; i < 5; i++ {
				if err := srv.Send(&pb.GenerateContentResponse{ResponseId: fmt.Sprintf("chunk-%d", i)}); err != nil {
					return err
				}
				select {
				case <-srv.Context().Done():
					close(streamCancelled)
					return srv.Context().Err()
				case <-time.After(15 * time.Millisecond):
				}
			}
			return nil
		},
	}

	target, stop := startFakeTLSServer(t, srvCert, fake, nil)
	defer stop()

	tokens := &stubTokenProvider{tokens: []string{"tok-tls-1"}}
	client, err := New(tokens, Options{
		UnaryTimeout:  5 * time.Second,
		StreamTimeout: 10 * time.Second,
		target:        target,
		tlsConfig:     &tls.Config{RootCAs: pool},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	cfg, err := client.FetchConfig(ctx)
	if err != nil || len(cfg.GetAvailableExperiences()) != 1 {
		t.Fatalf("FetchConfig failed: cfg=%v err=%v", cfg, err)
	}
	quota, err := client.FetchQuota(ctx)
	if err != nil || len(quota.GetBuckets()) != 1 {
		t.Fatalf("FetchQuota failed: quota=%v err=%v", quota, err)
	}

	var gotIDs []string
	stopErr := errors.New("stop early")
	err = client.Stream(ctx, &pb.GenerateContentRequest{SessionId: "sess-uuid"}, func(resp *pb.GenerateContentResponse) error {
		gotIDs = append(gotIDs, resp.GetResponseId())
		if len(gotIDs) == 2 {
			return stopErr
		}
		return nil
	})
	if !errors.Is(err, stopErr) {
		t.Fatalf("expected stopErr, got %v", err)
	}
	if len(gotIDs) != 2 || gotIDs[0] != "chunk-0" || gotIDs[1] != "chunk-1" {
		t.Fatalf("unexpected chunks: %v", gotIDs)
	}
	select {
	case <-streamCancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server stream cancellation")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 3 {
		t.Fatalf("expected 3 metadata records, got %d", len(captured))
	}
	for _, md := range captured {
		if authVals := md.Get("authorization"); len(authVals) != 1 || authVals[0] != "Bearer tok-tls-1" {
			t.Fatalf("unexpected authorization metadata: %v", authVals)
		}
		uaVals := md.Get("user-agent")
		if len(uaVals) != 1 || !strings.HasPrefix(uaVals[0], client.UserAgent()+" grpc-go/") {
			t.Fatalf("unexpected user-agent metadata: %v", uaVals)
		}
		for _, forbidden := range []string{"x-goog-api-key", "x-goog-user-project", "x-session-id"} {
			if vals := md.Get(forbidden); len(vals) > 0 {
				t.Fatalf("unexpected header %s: %v", forbidden, vals)
			}
		}
	}

	// Untrusted CA rejected cleanly without leaking cert details.
	wrongPool, _ := generateTestTLS(t, "other-ca")
	badCAClient, err := New(tokens, Options{
		UnaryTimeout:    2 * time.Second,
		target:          target,
		tlsConfig:       &tls.Config{RootCAs: wrongPool},
		retryBackoff:    0,
		retryBackoffSet: true,
	})
	if err != nil {
		t.Fatalf("New badCAClient: %v", err)
	}
	defer badCAClient.Close()

	_, err = badCAClient.FetchConfig(ctx)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != codes.Unavailable {
		t.Fatalf("expected *Error Unavailable on bad CA, got %v", err)
	}
	if strings.Contains(rpcErr.Error(), "x509") {
		t.Fatalf("raw TLS error leaked in Error(): %s", rpcErr.Error())
	}

	// Hostname mismatch rejected cleanly.
	mismatchPool, mismatchCert := generateTestTLS(t, "wrong.example")
	mismatchTarget, stopMismatch := startFakeTLSServer(t, mismatchCert, fake, nil)
	defer stopMismatch()

	mismatchClient, err := New(tokens, Options{
		UnaryTimeout:    2 * time.Second,
		target:          mismatchTarget,
		tlsConfig:       &tls.Config{RootCAs: mismatchPool},
		retryBackoff:    0,
		retryBackoffSet: true,
	})
	if err != nil {
		t.Fatalf("New mismatchClient: %v", err)
	}
	defer mismatchClient.Close()

	_, err = mismatchClient.FetchConfig(ctx)
	if !errors.As(err, &rpcErr) || rpcErr.Code != codes.Unavailable {
		t.Fatalf("expected *Error Unavailable on hostname mismatch, got %v", err)
	}

	// TLS 1.1-only server rejected due to MinVersion TLS 1.2.
	tls11Target, stopTLS11 := startFakeTLSServer(t, srvCert, fake, func(cfg *tls.Config) {
		cfg.MinVersion = tls.VersionTLS10
		cfg.MaxVersion = tls.VersionTLS11
	})
	defer stopTLS11()

	tls12Client, err := New(tokens, Options{
		UnaryTimeout:    2 * time.Second,
		target:          tls11Target,
		tlsConfig:       &tls.Config{RootCAs: pool},
		retryBackoff:    0,
		retryBackoffSet: true,
	})
	if err != nil {
		t.Fatalf("New tls12Client: %v", err)
	}
	defer tls12Client.Close()

	_, err = tls12Client.FetchConfig(ctx)
	if !errors.As(err, &rpcErr) || rpcErr.Code != codes.Unavailable {
		t.Fatalf("expected *Error Unavailable against TLS 1.1 server, got %v", err)
	}
}

func TestProbeUnauthenticated(t *testing.T) {
	pool, srvCert := generateTestTLS(t, "localhost")
	var seenAuth []string

	fake := &fakeServers{
		onFetchConfig: func(ctx context.Context, _ *pb.FetchConfigRequest) (*pb.FetchConfigResponse, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			seenAuth = append(seenAuth, md.Get("authorization")...)
			st := status.New(codes.Unauthenticated, "RAW_SECRET_MSG")
			st, _ = st.WithDetails(&errdetails.ErrorInfo{
				Reason: "CREDENTIALS_REQUIRED",
				Domain: "aicode.googleapis.com",
			})
			return nil, st.Err()
		},
	}

	target, stop := startFakeTLSServer(t, srvCert, fake, nil)
	defer stop()

	client, err := New(nil, Options{
		UnaryTimeout: 3 * time.Second,
		target:       target,
		tlsConfig:    &tls.Config{RootCAs: pool},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	res, err := client.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe unexpected error: %v", err)
	}
	if len(seenAuth) != 0 {
		t.Fatalf("Probe must not send authorization header, got %v", seenAuth)
	}
	if !res.ReachedEndpoint || res.Code != codes.Unauthenticated || res.Reason != "CREDENTIALS_REQUIRED" || res.Domain != "aicode.googleapis.com" {
		t.Fatalf("unexpected ProbeResult: %+v", res)
	}

	// Probe against untrusted CA fails with ReachedEndpoint=false.
	wrongPool, _ := generateTestTLS(t, "bad-ca")
	badClient, err := New(nil, Options{
		UnaryTimeout: 2 * time.Second,
		target:       target,
		tlsConfig:    &tls.Config{RootCAs: wrongPool},
	})
	if err != nil {
		t.Fatalf("New badClient: %v", err)
	}
	defer badClient.Close()

	resBad, errBad := badClient.Probe(context.Background())
	if errBad == nil || resBad.ReachedEndpoint || resBad.Code != codes.Unavailable {
		t.Fatalf("expected transport probe failure, got res=%+v err=%v", resBad, errBad)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	resCancelled, errCancelled := badClient.Probe(cancelled)
	if errCancelled == nil || resCancelled.ReachedEndpoint || resCancelled.Code != codes.Canceled {
		t.Fatalf("local cancellation must not count as upstream reachability: %+v, %v", resCancelled, errCancelled)
	}
}

func authFailure(reason string) error {
	st, err := status.New(codes.Unauthenticated, "synthetic auth failure").WithDetails(&errdetails.ErrorInfo{
		Reason: reason, Domain: "googleapis.com",
	})
	if err != nil {
		panic(err)
	}
	return st.Err()
}

func TestUnaryRetryPolicyAndTokenRefresh(t *testing.T) {
	pool, srvCert := generateTestTLS(t, "localhost")
	var cfgAttempts atomic.Int32
	var quotaAttempts atomic.Int32
	var mode atomic.Int32

	fake := &fakeServers{
		onFetchConfig: func(ctx context.Context, _ *pb.FetchConfigRequest) (*pb.FetchConfigResponse, error) {
			n := cfgAttempts.Add(1)
			switch mode.Load() {
			case 0: // Unavailable once -> retry once -> OK
				if n == 1 {
					return nil, status.Error(codes.Unavailable, "transient")
				}
				return &pb.FetchConfigResponse{}, nil
			case 1: // Always Unavailable -> 2 attempts max
				return nil, status.Error(codes.Unavailable, "still down")
			case 2: // Repeated explicit expiry -> 2 attempts max (1 refresh).
				return nil, authFailure("ACCESS_TOKEN_EXPIRED")
			case 7: // Invalid credentials without expiry do not trigger refresh.
				return nil, authFailure("CREDENTIALS_MISSING")
			case 8: // A plain Unauthenticated status also is not an expiry signal.
				return nil, status.Error(codes.Unauthenticated, "bad token")
			case 6: // DeadlineExceeded once -> retry once -> OK
				if n == 1 {
					return nil, status.Error(codes.DeadlineExceeded, "slow")
				}
				return &pb.FetchConfigResponse{}, nil
			default:
				return nil, status.Error(codes.PermissionDenied, "denied")
			}
		},
		onFetchQuota: func(ctx context.Context, _ *pb.FetchQuotaStatusRequest) (*pb.FetchQuotaStatusResponse, error) {
			n := quotaAttempts.Add(1)
			md, _ := metadata.FromIncomingContext(ctx)
			auth := md.Get("authorization")
			switch mode.Load() {
			case 3: // Unauthenticated -> refresh -> OK
				if n == 1 {
					if len(auth) != 1 || auth[0] != "Bearer tok-stale" {
						return nil, status.Error(codes.Internal, "expected stale token")
					}
					return nil, authFailure("ACCESS_TOKEN_EXPIRED")
				}
				if len(auth) != 1 || auth[0] != "Bearer tok-fresh" {
					return nil, status.Error(codes.Internal, "expected fresh token")
				}
				return &pb.FetchQuotaStatusResponse{}, nil
			case 4: // ResourceExhausted -> NO retry
				return nil, status.Error(codes.ResourceExhausted, "quota exceeded")
			default:
				return nil, status.Error(codes.PermissionDenied, "denied")
			}
		},
	}

	target, stop := startFakeTLSServer(t, srvCert, fake, nil)
	defer stop()

	ctx := context.Background()
	makeClient := func(tp TokenProvider) *Client {
		c, err := New(tp, Options{
			UnaryTimeout:    3 * time.Second,
			target:          target,
			tlsConfig:       &tls.Config{RootCAs: pool},
			retryBackoff:    0,
			retryBackoffSet: true,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return c
	}

	// 1. Unavailable once -> retries once and succeeds.
	mode.Store(0)
	cfgAttempts.Store(0)
	c1 := makeClient(&stubTokenProvider{tokens: []string{"tok-1"}})
	defer c1.Close()
	if _, err := c1.FetchConfig(ctx); err != nil {
		t.Fatalf("expected FetchConfig recovery, got %v", err)
	}
	if cfgAttempts.Load() != 2 {
		t.Fatalf("expected 2 attempts, got %d", cfgAttempts.Load())
	}

	// 2. Unavailable twice -> stops after 2 attempts.
	mode.Store(1)
	cfgAttempts.Store(0)
	if _, err := c1.FetchConfig(ctx); err == nil {
		t.Fatal("expected error after 2 Unavailable attempts")
	}
	if cfgAttempts.Load() != 2 {
		t.Fatalf("expected 2 attempts, got %d", cfgAttempts.Load())
	}

	// 3. Unauthenticated -> refreshes once with rejected="tok-stale" and succeeds.
	mode.Store(3)
	quotaAttempts.Store(0)
	tpRefresh := &stubTokenProvider{tokens: []string{"tok-stale", "tok-fresh"}}
	c2 := makeClient(tpRefresh)
	defer c2.Close()
	if _, err := c2.FetchQuota(ctx); err != nil {
		t.Fatalf("expected FetchQuota recovery after refresh, got %v", err)
	}
	if quotaAttempts.Load() != 2 {
		t.Fatalf("expected 2 attempts, got %d", quotaAttempts.Load())
	}
	if calls := tpRefresh.recordedCalls(); len(calls) != 2 || calls[0] != "" || calls[1] != "tok-stale" {
		t.Fatalf("unexpected token calls: %v", calls)
	}

	// 4. Unauthenticated twice -> stops after 1 refresh.
	mode.Store(2)
	cfgAttempts.Store(0)
	tpTwice := &stubTokenProvider{tokens: []string{"tok-a", "tok-b"}}
	c3 := makeClient(tpTwice)
	defer c3.Close()
	_, err := c3.FetchConfig(ctx)
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated *Error, got %v", err)
	}
	if cfgAttempts.Load() != 2 {
		t.Fatalf("expected 2 attempts, got %d", cfgAttempts.Load())
	}

	// 5. PermissionDenied & ResourceExhausted -> NO retry.
	mode.Store(5)
	cfgAttempts.Store(0)
	_, err = c3.FetchConfig(ctx)
	if !errors.As(err, &rpcErr) || rpcErr.Code != codes.PermissionDenied || cfgAttempts.Load() != 1 {
		t.Fatalf("expected single PermissionDenied attempt, got err=%v attempts=%d", err, cfgAttempts.Load())
	}

	mode.Store(4)
	quotaAttempts.Store(0)
	_, err = c3.FetchQuota(ctx)
	if !errors.As(err, &rpcErr) || rpcErr.Code != codes.ResourceExhausted || quotaAttempts.Load() != 1 {
		t.Fatalf("expected single ResourceExhausted attempt, got err=%v attempts=%d", err, quotaAttempts.Load())
	}

	// 6. DeadlineExceeded once -> retries once and succeeds.
	mode.Store(6)
	cfgAttempts.Store(0)
	if _, err := c1.FetchConfig(ctx); err != nil {
		t.Fatalf("expected FetchConfig recovery after DeadlineExceeded, got %v", err)
	}
	if cfgAttempts.Load() != 2 {
		t.Fatalf("expected 2 attempts for DeadlineExceeded, got %d", cfgAttempts.Load())
	}

	for _, n := range []int32{7, 8} {
		mode.Store(n)
		cfgAttempts.Store(0)
		tp := &stubTokenProvider{tokens: []string{"tok-current"}}
		c := makeClient(tp)
		_, err := c.FetchConfig(ctx)
		_ = c.Close()
		if !errors.As(err, &rpcErr) || rpcErr.Code != codes.Unauthenticated || cfgAttempts.Load() != 1 {
			t.Fatalf("expected one unauthenticated request without expiry: %v, attempts=%d", err, cfgAttempts.Load())
		}
		if calls := tp.recordedCalls(); len(calls) != 1 || calls[0] != "" {
			t.Fatalf("non-expiry auth error triggered token refresh: %v", calls)
		}
	}
}

type coalescingTokenProvider struct {
	mu           sync.Mutex
	current      string
	calls        []string
	refreshCount int
}

func (p *coalescingTokenProvider) AccessToken(_ context.Context, rejected string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, rejected)
	if rejected != "" && rejected == p.current {
		time.Sleep(20 * time.Millisecond)
		p.refreshCount++
		p.current = fmt.Sprintf("tok-%d", p.refreshCount+1)
	}
	return p.current, nil
}

func TestStreamNoRetryAndCoalescedRejectedRefresh(t *testing.T) {
	pool, srvCert := generateTestTLS(t, "localhost")
	var streamCalls atomic.Int32
	var forceCode atomic.Int32

	fake := &fakeServers{
		onFetchQuota: func(ctx context.Context, _ *pb.FetchQuotaStatusRequest) (*pb.FetchQuotaStatusResponse, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			auth := md.Get("authorization")
			if len(auth) != 1 || auth[0] != "Bearer tok-2" {
				return nil, status.Error(codes.Unauthenticated, "expected tok-2")
			}
			return &pb.FetchQuotaStatusResponse{}, nil
		},
		onStream: func(req *pb.GenerateContentRequest, srv grpc.ServerStreamingServer[pb.GenerateContentResponse]) error {
			streamCalls.Add(1)
			if code := codes.Code(forceCode.Load()); code != codes.OK {
				return status.Error(code, "pre-first-chunk fail")
			}
			md, _ := metadata.FromIncomingContext(srv.Context())
			auth := md.Get("authorization")
			if len(auth) == 1 && auth[0] == "Bearer tok-1" {
				return authFailure("ACCESS_TOKEN_EXPIRED")
			}
			return srv.Send(&pb.GenerateContentResponse{ResponseId: "ok-after-refresh"})
		},
	}

	target, stop := startFakeTLSServer(t, srvCert, fake, nil)
	defer stop()

	ctx := context.Background()

	// Pre-first-chunk Unavailable -> NO retry (WithDisableRetry + no app retry).
	forceCode.Store(int32(codes.Unavailable))
	cNoRetry, err := New(&stubTokenProvider{tokens: []string{"tok-1"}}, Options{
		UnaryTimeout:    3 * time.Second,
		StreamTimeout:   5 * time.Second,
		target:          target,
		tlsConfig:       &tls.Config{RootCAs: pool},
		retryBackoff:    0,
		retryBackoffSet: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cNoRetry.Close()

	err = cNoRetry.Stream(ctx, &pb.GenerateContentRequest{}, func(*pb.GenerateContentResponse) error { return nil })
	var rpcErr *Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != codes.Unavailable || streamCalls.Load() != 1 {
		t.Fatalf("expected single Unavailable stream attempt, got err=%v calls=%d", err, streamCalls.Load())
	}

	// Stream Unauthenticated does not replay, records tok-1, and next concurrent calls coalesce refresh.
	forceCode.Store(int32(codes.OK))
	streamCalls.Store(0)
	tp := &coalescingTokenProvider{current: "tok-1"}
	c, err := New(tp, Options{
		UnaryTimeout:    3 * time.Second,
		StreamTimeout:   5 * time.Second,
		target:          target,
		tlsConfig:       &tls.Config{RootCAs: pool},
		retryBackoff:    0,
		retryBackoffSet: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.Stream(ctx, &pb.GenerateContentRequest{}, func(*pb.GenerateContentResponse) error { return nil })
	if !errors.As(err, &rpcErr) || rpcErr.Code != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated *Error, got %v", err)
	}
	if streamCalls.Load() != 1 {
		t.Fatalf("expected 1 stream attempt (no replay), got %d", streamCalls.Load())
	}

	var wg sync.WaitGroup
	var sErr, qErr error
	var sRespID string
	wg.Add(2)
	go func() {
		defer wg.Done()
		sErr = c.Stream(ctx, &pb.GenerateContentRequest{}, func(resp *pb.GenerateContentResponse) error {
			sRespID = resp.GetResponseId()
			return nil
		})
	}()
	go func() {
		defer wg.Done()
		_, qErr = c.FetchQuota(ctx)
	}()
	wg.Wait()

	if sErr != nil || qErr != nil || sRespID != "ok-after-refresh" {
		t.Fatalf("concurrent post-refresh failed: sErr=%v qErr=%v id=%s", sErr, qErr, sRespID)
	}
	tp.mu.Lock()
	refreshes := tp.refreshCount
	tp.mu.Unlock()
	if refreshes != 1 {
		t.Fatalf("expected exactly 1 coalesced refresh, got %d", refreshes)
	}

	// Late rejection of already-replaced tok-1 must not re-invalidate tok-2.
	c.recordRejectedToken("tok-1")
	if c.peekRejectedToken() != "" {
		t.Fatalf("expected replaced tok-1 to be ignored, got %q", c.peekRejectedToken())
	}
	if _, err := c.FetchQuota(ctx); err != nil {
		t.Fatalf("FetchQuota after late stale rejection: %v", err)
	}
	tp.mu.Lock()
	refreshesAfter := tp.refreshCount
	tp.mu.Unlock()
	if refreshesAfter != 1 {
		t.Fatalf("expected refreshCount to remain 1, got %d", refreshesAfter)
	}

	// Close() rejects subsequent calls cleanly.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
	if _, err := c.FetchConfig(ctx); !errors.As(err, &rpcErr) || rpcErr.Code != codes.Canceled || rpcErr.Reason != "CLIENT_CLOSED" {
		t.Fatalf("expected CLIENT_CLOSED after Close, got %v", err)
	}
}

func TestTokenProviderErrorNotSwallowedAndASCIIValidation(t *testing.T) {
	pool, srvCert := generateTestTLS(t, "localhost")
	fake := &fakeServers{
		onFetchConfig: func(ctx context.Context, _ *pb.FetchConfigRequest) (*pb.FetchConfigResponse, error) {
			return &pb.FetchConfigResponse{}, nil
		},
	}
	target, stop := startFakeTLSServer(t, srvCert, fake, nil)
	defer stop()

	sentinelAuthErr := errors.New("auth_required: login needed")
	cAuthErr, err := New(&stubTokenProvider{err: sentinelAuthErr}, Options{
		UnaryTimeout: 2 * time.Second,
		target:       target,
		tlsConfig:    &tls.Config{RootCAs: pool},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cAuthErr.Close()

	_, err = cAuthErr.FetchConfig(context.Background())
	if !errors.Is(err, sentinelAuthErr) {
		t.Fatalf("expected TokenProvider error to propagate unswallowed, got %v", err)
	}
	cAuthErr.recordRejectedToken("tok-old")
	_, err = cAuthErr.FetchQuota(context.Background())
	if !errors.Is(err, sentinelAuthErr) {
		t.Fatalf("expected TokenProvider error in locked path to propagate unswallowed, got %v", err)
	}

	for _, badTok := range []string{"", "tok-é", "tok with space", "tok\nheader"} {
		cBadTok, err := New(&stubTokenProvider{tokens: []string{badTok}}, Options{
			UnaryTimeout: 2 * time.Second,
			target:       target,
			tlsConfig:    &tls.Config{RootCAs: pool},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, callErr := cBadTok.FetchConfig(context.Background())
		_ = cBadTok.Close()

		var rpcErr *Error
		if !errors.As(callErr, &rpcErr) || rpcErr.Code != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated for bad token %q, got %v", badTok, callErr)
		}
	}
}

func TestErrorSanitization(t *testing.T) {
	pool, srvCert := generateTestTLS(t, "localhost")
	var callNum atomic.Int32

	fake := &fakeServers{
		onFetchConfig: func(ctx context.Context, _ *pb.FetchConfigRequest) (*pb.FetchConfigResponse, error) {
			if callNum.Add(1) == 1 {
				st := status.New(codes.ResourceExhausted, "Prompt failed: SECRET_PROMPT fake-oauth-token-REDACTION_TEST_ONLY")
				st, _ = st.WithDetails(
					&errdetails.ErrorInfo{
						Reason:   "RATE_LIMIT_EXCEEDED",
						Domain:   "aicode.googleapis.com",
						Metadata: map[string]string{"prompt": "SECRET_PROMPT", "project": "secret-proj"},
					},
					&errdetails.RetryInfo{
						RetryDelay: durationpb.New(15*time.Second + 500*time.Millisecond),
					},
				)
				return nil, st.Err()
			}
			_ = grpc.SetTrailer(ctx, metadata.Pairs("retry-after", "25"))
			st := status.New(codes.Internal, "raw secret message")
			st, _ = st.WithDetails(&errdetails.ErrorInfo{
				Reason: "invalid reason with spaces/SECRET",
				Domain: "bad domain!",
			})
			return nil, st.Err()
		},
	}

	target, stop := startFakeTLSServer(t, srvCert, fake, nil)
	defer stop()

	c, err := New(&stubTokenProvider{tokens: []string{"fake-oauth-token-REDACTION_TEST_ONLY"}}, Options{
		UnaryTimeout:    2 * time.Second,
		target:          target,
		tlsConfig:       &tls.Config{RootCAs: pool},
		retryBackoff:    0,
		retryBackoffSet: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	_, err = c.FetchConfig(context.Background())
	var rpcErr *Error
	if !errors.As(err, &rpcErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if rpcErr.Code != codes.ResourceExhausted || rpcErr.RPC != rpcFetchConfig {
		t.Fatalf("unexpected Code/RPC: %+v", rpcErr)
	}
	if rpcErr.Reason != "RATE_LIMIT_EXCEEDED" || rpcErr.Domain != "aicode.googleapis.com" {
		t.Fatalf("unexpected Reason/Domain: %+v", rpcErr)
	}
	if rpcErr.RetryAfter != 15*time.Second+500*time.Millisecond {
		t.Fatalf("unexpected RetryAfter: %v", rpcErr.RetryAfter)
	}
	msg := rpcErr.Error()
	for _, forbidden := range []string{"SECRET_PROMPT", "fake-oauth-token-REDACTION_TEST_ONLY", "secret-proj"} {
		if strings.Contains(msg, forbidden) {
			t.Fatalf("sanitized Error() leaked %q: %s", forbidden, msg)
		}
	}

	_, err = c.FetchConfig(context.Background())
	if !errors.As(err, &rpcErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if rpcErr.Reason != "" || rpcErr.Domain != "" {
		t.Fatalf("expected non-canonical reason/domain dropped, got %+v", rpcErr)
	}
	if rpcErr.RetryAfter != 25*time.Second {
		t.Fatalf("expected trailing retry-after=25s, got %v", rpcErr.RetryAfter)
	}
}
