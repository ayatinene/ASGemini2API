package aicode

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const maxRetryAfter = 7 * 24 * time.Hour

var (
	reasonPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	domainPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,126}[A-Za-z0-9])?$`)
)

// Error is a typed, strictly sanitized gRPC error.
// It never exposes raw upstream Status.Message, ErrorInfo.Metadata,
// request payloads, or bearer tokens.
type Error struct {
	Code       codes.Code
	RPC        string
	Reason     string
	Domain     string
	RetryAfter time.Duration
	Guidance   string
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	var parts []string
	parts = append(parts, fmt.Sprintf("rpc=%s", e.RPC))
	parts = append(parts, fmt.Sprintf("code=%s", e.Code.String()))
	if e.Reason != "" {
		parts = append(parts, fmt.Sprintf("reason=%s", e.Reason))
	}
	if e.Domain != "" {
		parts = append(parts, fmt.Sprintf("domain=%s", e.Domain))
	}
	if e.RetryAfter > 0 {
		parts = append(parts, fmt.Sprintf("retry_after=%s", e.RetryAfter))
	}
	guidance := e.Guidance
	if guidance == "" {
		guidance = statusGuidance(e.Code)
	}
	return fmt.Sprintf("aicode.Error(%s): %s", strings.Join(parts, ", "), guidance)
}

func statusGuidance(code codes.Code) string {
	switch code {
	case codes.OK:
		return "Call succeeded."
	case codes.Canceled:
		return "RPC call was cancelled."
	case codes.Unknown:
		return "Unknown gRPC failure."
	case codes.InvalidArgument:
		return "Request rejected as invalid argument; verify request fields."
	case codes.DeadlineExceeded:
		return "RPC deadline exceeded before completion."
	case codes.NotFound:
		return "Requested method or resource was not found."
	case codes.AlreadyExists:
		return "Resource already exists."
	case codes.PermissionDenied:
		return "Access denied by service; do not retry automatically."
	case codes.ResourceExhausted:
		return "Quota or rate limit exhausted; honor retry hint and wait before retrying."
	case codes.FailedPrecondition:
		return "Request failed a server precondition."
	case codes.Aborted:
		return "Operation aborted."
	case codes.OutOfRange:
		return "Parameter out of range."
	case codes.Unimplemented:
		return "RPC method is not implemented by the endpoint."
	case codes.Internal:
		return "Internal service error."
	case codes.Unavailable:
		return "Endpoint or transport unavailable (TLS, DNS, network, or transient outage)."
	case codes.DataLoss:
		return "Unrecoverable data loss reported by service."
	case codes.Unauthenticated:
		return "Authentication failed or OAuth bearer token was rejected."
	default:
		return "gRPC call failed."
	}
}

func sanitizeReason(raw string) string {
	if reasonPattern.MatchString(raw) {
		return raw
	}
	return ""
}

func sanitizeDomain(raw string) string {
	if domainPattern.MatchString(raw) {
		return raw
	}
	return ""
}

func sanitizeRetryAfter(d time.Duration) time.Duration {
	if d <= 0 || d > maxRetryAfter {
		return 0
	}
	return d
}

func parseRPCError(err error, rpcName string, trailer metadata.MD) *Error {
	if err == nil {
		return nil
	}
	var existing *Error
	if errors.As(err, &existing) {
		return existing
	}

	st, ok := status.FromError(err)
	code := codes.Unknown
	if ok {
		code = st.Code()
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		code = status.FromContextError(err).Code()
	}
	if code == codes.OK {
		code = codes.Unknown
	}

	out := &Error{
		Code:     code,
		RPC:      rpcName,
		Guidance: statusGuidance(code),
	}

	if ok {
		for _, detail := range st.Details() {
			switch d := detail.(type) {
			case *errdetails.ErrorInfo:
				if out.Reason == "" {
					out.Reason = sanitizeReason(d.GetReason())
				}
				if out.Domain == "" {
					out.Domain = sanitizeDomain(d.GetDomain())
				}
			case *errdetails.RetryInfo:
				if out.RetryAfter == 0 && d.GetRetryDelay() != nil && d.GetRetryDelay().IsValid() {
					delay := d.GetRetryDelay().AsDuration()
					if !math.IsNaN(delay.Seconds()) {
						out.RetryAfter = sanitizeRetryAfter(delay)
					}
				}
			}
		}
	}

	if out.RetryAfter == 0 && trailer != nil {
		for _, val := range trailer.Get("retry-after") {
			trimmed := strings.TrimSpace(val)
			if len(trimmed) == 0 || len(trimmed) > 6 {
				continue
			}
			secs, convErr := strconv.Atoi(trimmed)
			if convErr == nil && secs > 0 {
				out.RetryAfter = sanitizeRetryAfter(time.Duration(secs) * time.Second)
				break
			}
		}
	}

	return out
}
