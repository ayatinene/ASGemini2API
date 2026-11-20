package settings

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	StateDir, InputDir, OAuthClientFile string
	UnaryTimeout, StreamTimeout         time.Duration
	CatalogTTL, QuotaTTL                time.Duration
	MaxBodyBytes                        int64
	MaxInFlight                         int
	// LoginRedirectPort is the loopback port advertised by the admin OAuth
	// flow. The browser only needs to reach it when an SSH tunnel is used;
	// otherwise the operator copies the failing callback URL back.
	LoginRedirectPort int
}

func FromEnv(stateDir, inputDir string) (Config, error) {
	if stateDir == "" {
		stateDir = os.Getenv("ASGEMINI_STATE_DIR")
	}
	if stateDir == "" {
		xdg := os.Getenv("XDG_STATE_HOME")
		if xdg == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return Config{}, fmt.Errorf("set ASGEMINI_STATE_DIR when HOME is unavailable")
			}
			xdg = filepath.Join(home, ".local", "state")
		}
		stateDir = filepath.Join(xdg, "asgemini2api")
	}
	if inputDir == "" {
		inputDir = env("ASGEMINI_INPUT_DIR", "runtime")
	}
	c := Config{
		StateDir: stateDir, InputDir: inputDir,
		OAuthClientFile: env("ASGEMINI_OAUTH_CLIENT_FILE", filepath.Join(inputDir, "oauth-client.json")),
	}
	for _, spec := range []struct {
		name        string
		value       *time.Duration
		def, lo, hi time.Duration
	}{
		{"ASGEMINI_UNARY_TIMEOUT", &c.UnaryTimeout, 15 * time.Second, time.Second, 2 * time.Minute},
		{"ASGEMINI_STREAM_TIMEOUT", &c.StreamTimeout, 5 * time.Minute, 5 * time.Second, 30 * time.Minute},
		{"ASGEMINI_CATALOG_TTL", &c.CatalogTTL, 24 * time.Hour, 30 * time.Second, 24 * time.Hour},
		{"ASGEMINI_QUOTA_TTL", &c.QuotaTTL, 30 * time.Second, time.Second, 10 * time.Minute},
	} {
		value, err := time.ParseDuration(env(spec.name, spec.def.String()))
		if err != nil || value < spec.lo || value > spec.hi {
			return Config{}, fmt.Errorf("%s must be a duration between %s and %s", spec.name, spec.lo, spec.hi)
		}
		*spec.value = value
	}
	body, err := boundedInt("ASGEMINI_MAX_BODY_BYTES", 2<<20, 4<<10, 16<<20)
	if err != nil {
		return Config{}, err
	}
	c.MaxBodyBytes = int64(body)
	c.MaxInFlight, err = boundedInt("ASGEMINI_MAX_IN_FLIGHT", 4, 1, 32)
	if err != nil {
		return Config{}, err
	}
	c.LoginRedirectPort, err = boundedInt("ASGEMINI_LOGIN_REDIRECT_PORT", 14535, 1, 65535)
	return c, err
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func boundedInt(key string, fallback, minValue, maxValue int) (int, error) {
	n, err := strconv.Atoi(env(key, strconv.Itoa(fallback)))
	if err != nil || n < minValue || n > maxValue {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, minValue, maxValue)
	}
	return n, nil
}

// Keys stores only digests; log and application structs never contain bearer keys.
type Keys struct {
	API, Admin [sha256.Size]byte
}

func LoadKeys() (Keys, error) {
	api, err := secret("ASGEMINI_API_KEY")
	if err != nil {
		return Keys{}, err
	}
	admin, err := secret("ASGEMINI_ADMIN_KEY")
	if err != nil {
		return Keys{}, err
	}
	if api == admin {
		return Keys{}, fmt.Errorf("API and admin keys must be distinct")
	}
	return Keys{API: api, Admin: admin}, nil
}

func secret(key string) ([sha256.Size]byte, error) {
	value := os.Getenv(key)
	if filename := os.Getenv(key + "_FILE"); filename != "" {
		if value != "" {
			return [sha256.Size]byte{}, fmt.Errorf("set only %s or %s_FILE", key, key)
		}
		file, err := os.Open(filename)
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("cannot open %s_FILE", key)
		}
		defer file.Close()
		st, err := file.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() > 1026 {
			return [sha256.Size]byte{}, fmt.Errorf("%s_FILE must be a small regular file", key)
		}
		raw, err := io.ReadAll(io.LimitReader(file, 1027))
		if err != nil || len(raw) > 1026 {
			return [sha256.Size]byte{}, fmt.Errorf("cannot read %s_FILE", key)
		}
		value = strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	}
	if len(value) < 24 || len(value) > 1024 || strings.HasPrefix(value, "replace-with-") {
		return [sha256.Size]byte{}, fmt.Errorf("%s needs a unique secret with 24–1024 printable ASCII characters", key)
	}
	for i := range len(value) {
		if value[i] < '!' || value[i] > '~' {
			return [sha256.Size]byte{}, fmt.Errorf("%s must not contain whitespace or non-ASCII characters", key)
		}
	}
	return sha256.Sum256([]byte(value)), nil
}
