package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/aicode"
	"github.com/ayatinene/ASGemini2API/internal/auth"
	"github.com/ayatinene/ASGemini2API/internal/chat"
	"github.com/ayatinene/ASGemini2API/internal/gateway"
	"github.com/ayatinene/ASGemini2API/internal/settings"
	"golang.org/x/sys/unix"
)

const usage = `ASGemini2API — headless Android Studio Gemini proxy

Usage: asgemini2api [global flags] <command> [flags]
Global flags (before the command):
  --input-dir PATH  Directory holding local configuration files
  --state-dir PATH  Private directory containing the single account state

Commands:
  check-inputs   Validate the deployment's OAuth Desktop client file offline
  inspect-studio Inspect packaged flags in a pinned android-common.jar (offline)
  login          Authorize this deployment's Desktop client (loopback + PKCE)
  status         Inspect local account state without contacting Google
  logout         Remove local credentials (does not revoke the grant at Google)
  probe          Make one unauthenticated FetchConfig RPC
  models         Query the account's real AiCode model discovery
  quota          Query the account's real AiCode quota status
  verify         Query models and quota, optionally run one short generation
  serve          Run the OpenAI-compatible HTTP service and admin endpoints
  healthcheck    Exit successfully if the local HTTP liveness check responds

Run asgemini2api <command> --help for command flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		reportError(os.Stderr, err)
		if ctx.Err() != nil {
			os.Exit(130)
		}
		os.Exit(1)
	}
}

func jsonOutput(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func reportError(w io.Writer, err error) {
	fields := map[string]any{"code": "local_error", "message": err.Error()}
	var rpc *aicode.Error
	var credential *auth.Error
	var bridge *chat.Error
	switch {
	case errors.As(err, &rpc):
		fields = map[string]any{"stage": "aicode_rpc", "code": rpc.Code.String(), "rpc": rpc.RPC, "message": rpc.Error()}
		if rpc.Reason != "" {
			fields["reason"] = rpc.Reason
		}
		if rpc.Domain != "" {
			fields["domain"] = rpc.Domain
		}
		if rpc.RetryAfter > 0 {
			fields["retry_after_seconds"] = rpc.RetryAfter.Seconds()
		}
	case errors.As(err, &credential):
		fields["code"] = credential.Code
		if credential.Stage != "" {
			fields["stage"] = credential.Stage
		}
		if credential.Status != 0 {
			fields["http_status"] = credential.Status
		}
		if credential.RetryAfter > 0 {
			fields["retry_after_seconds"] = credential.RetryAfter.Seconds()
		}
	case errors.As(err, &bridge):
		fields["code"] = bridge.Code
	default:
		var evidence *verificationError
		if errors.As(err, &evidence) {
			fields["stage"] = "aicode_verification"
			fields["code"] = evidence.code
			fields["check"] = evidence.check
		}
	}
	var step *verificationCallError
	if errors.As(err, &step) {
		fields["check"] = step.check
		if step.attempted {
			fields["generation_attempted"] = true
		}
	}
	_ = jsonOutput(w, map[string]any{"error": fields})
}

func commandFlags(name string, output io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(output)
	f.Usage = func() {
		fmt.Fprintf(output, "Usage: asgemini2api %s [flags]\n", name)
		f.PrintDefaults()
	}
	return f
}

func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() > 0 {
		return errors.New("unexpected positional arguments")
	}
	return nil
}

func lockState(path string) (func(), error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("create private state directory: %w", err)
	}
	dir, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("state directory must be a real directory, not a symlink")
	}
	defer unix.Close(dir)
	var st unix.Stat_t
	if unix.Fstat(dir, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0o077 != 0 {
		return nil, errors.New("state directory must be owned by the current user with permissions 0700")
	}
	fd, err := unix.Openat(dir, ".session.lock", unix.O_CREAT|unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, errors.New("could not open the private state lock")
	}
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0o077 != 0 {
		unix.Close(fd)
		return nil, errors.New("state lock must be an owner-only regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("this state directory is in use; stop serve or use the admin API")
		}
		return nil, fmt.Errorf("lock state directory: %w", err)
	}
	return func() { unix.Close(fd) }, nil
}

func run(ctx context.Context, args []string, out, diagnostics io.Writer) error {
	root := flag.NewFlagSet("asgemini2api", flag.ContinueOnError)
	root.SetOutput(diagnostics)
	root.Usage = func() { fmt.Fprint(out, usage) }
	state := root.String("state-dir", "", "private runtime state directory")
	inputs := root.String("input-dir", "", "local configuration directory")
	if err := root.Parse(args); err != nil {
		return err
	}
	if root.NArg() == 0 || root.Arg(0) == "help" {
		root.Usage()
		return nil
	}
	cmd, rest := root.Arg(0), root.Args()[1:]
	f := commandFlags(cmd, diagnostics)
	var port *int
	var host, model, healthURL, commonJar *string
	var timeout *time.Duration
	var generate *bool
	switch cmd {
	case "inspect-studio":
		commonJar = f.String("common-jar", "", "local path to the pinned android-common.jar (required)")
	case "login":
		port = f.Int("port", 0, "fixed IPv4 loopback callback port (default: automatic)")
		timeout = f.Duration("timeout", 5*time.Minute, "maximum time to wait for browser authorization")
	case "verify":
		generate = f.Bool("generate", false, "send one short generation (can consume Android Studio quota)")
		model = f.String("model", "", "discovered model ID (defaults to the first model)")
	case "serve":
		host = f.String("host", "127.0.0.1", "HTTP bind address")
		port = f.Int("port", 8080, "HTTP port")
	case "healthcheck":
		healthURL = f.String("url", "http://127.0.0.1:8080/healthz", "IPv4 loopback health URL")
	case "check-inputs", "status", "logout", "models", "quota", "probe":
	default:
		return errors.New("unknown command; run asgemini2api --help")
	}
	if err := parse(f, rest); err != nil {
		return err
	}
	if healthURL != nil {
		return healthcheck(ctx, *healthURL)
	}
	if commonJar != nil {
		if *commonJar == "" {
			return errors.New("inspect-studio requires --common-jar")
		}
		flags, err := auth.InspectStudioPackage(*commonJar)
		if err != nil {
			return err
		}
		return jsonOutput(out, map[string]any{
			"build": auth.StudioBuild, "channel": "stable", "packaged_defaults": flags,
			"runtime_observed": false,
		})
	}
	if port != nil && (*port < 0 || *port > 65535 || (cmd == "serve" && *port == 0)) {
		return errors.New("invalid port")
	}
	if timeout != nil && (*timeout < 15*time.Second || *timeout > 15*time.Minute) {
		return errors.New("login timeout must be between 15s and 15m")
	}
	if model != nil && *model != "" && !*generate {
		return errors.New("--model requires --generate")
	}

	cfg, err := settings.FromEnv(*state, *inputs)
	if err != nil {
		return err
	}
	options := aicode.Options{UnaryTimeout: cfg.UnaryTimeout, StreamTimeout: cfg.StreamTimeout}
	if cmd == "probe" {
		client, err := aicode.New(nil, options)
		if err != nil {
			return err
		}
		defer client.Close()
		result, err := client.Probe(ctx)
		if err != nil {
			return err
		}
		if err := jsonOutput(out, map[string]any{
			"endpoint": result.Endpoint, "user_agent": result.UserAgent, "rpc": result.RPC,
			"reached_endpoint": result.ReachedEndpoint, "status": result.Code.String(),
			"reason": result.Reason, "domain": result.Domain, "guidance": result.Guidance, "stage": "aicode_rpc",
		}); err != nil {
			return err
		}
		if !result.ReachedEndpoint {
			return errors.New("probe did not receive a confirmed upstream gRPC status")
		}
		return nil
	}
	if cmd == "logout" {
		unlock, err := lockState(cfg.StateDir)
		if err != nil {
			return err
		}
		defer unlock()
		had, err := auth.ClearLocalSession(cfg.StateDir)
		if err != nil {
			return err
		}
		return jsonOutput(out, map[string]any{"logged_out": true, "had_session": had})
	}
	profile, err := auth.LoadDesktopClient(cfg.OAuthClientFile)
	var inputErr *auth.Error
	if err != nil && !(errors.As(err, &inputErr) && inputErr.Code == "oauth_client_not_configured" && (cmd == "serve" || cmd == "status")) {
		return err
	}
	if cmd == "check-inputs" {
		return jsonOutput(out, map[string]any{"valid_config": true, "client_type": "desktop", "requested_scope_count": len(profile.Scopes), "google_client_admission": "not_checked"})
	}
	var tokens *auth.Manager
	if err == nil {
		tokens = auth.NewManager(profile, cfg.StateDir)
	} else {
		tokens = auth.NewUnconfiguredManager()
	}
	if cmd == "status" {
		status, err := tokens.Status()
		if err != nil {
			return err
		}
		return jsonOutput(out, status)
	}
	unlock, err := lockState(cfg.StateDir)
	if err != nil {
		return err
	}
	defer unlock()

	switch cmd {
	case "login":
		ctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		result, err := tokens.Login(ctx, *port, func(link string) error {
			_, err := fmt.Fprintf(diagnostics, "Open the Google authorization link in the browser that can reach the loopback callback. Do not share the link or callback:\n%s\n", link)
			return err
		})
		if err != nil {
			return err
		}
		return jsonOutput(out, map[string]any{"logged_in": result.LoggedIn, "email": result.Email, "aicode_access": "not_checked"})
	}

	client, err := aicode.New(tokens, options)
	if err != nil {
		return err
	}
	defer client.Close()
	if cmd == "serve" {
		keys, err := settings.LoadKeys()
		if err != nil {
			return err
		}
		if _, err := tokens.Status(); err != nil {
			return err
		}
		if strings.TrimSpace(*host) == "" {
			return errors.New("serve requires an explicit bind address")
		}
		return serve(ctx, net.JoinHostPort(*host, strconv.Itoa(*port)), gateway.New(client, tokens, cfg, keys, slog.New(slog.NewJSONHandler(diagnostics, nil))).Handler(), diagnostics)
	}
	selectTimeout := 3*cfg.UnaryTimeout + 20*time.Second
	switch cmd {
	case "models":
		ctx, cancel := context.WithTimeout(ctx, selectTimeout)
		defer cancel()
		response, err := client.FetchConfig(ctx)
		if err != nil {
			return err
		}
		return jsonOutput(out, map[string]any{"fetched_at": time.Now().UTC(), "models": aicode.Models(response)})
	case "quota":
		ctx, cancel := context.WithTimeout(ctx, selectTimeout)
		defer cancel()
		response, err := client.FetchQuota(ctx)
		if err != nil {
			return err
		}
		return jsonOutput(out, map[string]any{"fetched_at": time.Now().UTC(), "buckets": aicode.Quota(response)})
	case "verify":
		return verify(ctx, client, cfg, out, *generate, *model)
	}
	return nil
}

func healthcheck(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.Path != "/healthz" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("healthcheck URL must use http://127.0.0.1:<port>/healthz")
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return errors.New("invalid healthcheck URL")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("local health endpoint unreachable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}

func serve(ctx context.Context, address string, handler http.Handler, diagnostics io.Writer) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	requestContext, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second,
		IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10,
		BaseContext: func(_ net.Listener) context.Context { return requestContext },
	}
	logger := slog.New(slog.NewJSONHandler(diagnostics, nil))
	logger.Info("http_listening", "address", listener.Addr().String())
	if host, _, err := net.SplitHostPort(address); err == nil {
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			logger.Warn("admin_plaintext_bind", "address", address, "detail", "admin endpoints accept a Bearer key over plaintext HTTP; bind loopback or terminate TLS in front of this listener")
		}
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err = <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		cancelRequests()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
	}
	return nil
}
