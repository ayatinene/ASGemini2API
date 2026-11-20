package auth

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

const (
	StudioBuild        = "AI-262.10968.63.2622.16840690"
	pinnedCommonSHA256 = "7cd8d99a8ccda83172b3747ccc45362cc70899aed3a5e4458fed11bc2af1eab0"
	pinnedFlagsSHA256  = "78104148be56fafae71531799d34a6439d0ca313f5e0aef00c35c1d997639da5"
	use1PFlag          = "google.login.use.1p.login.ui"
	useFSTFlag         = "google.login.enable.fsts"
	featureFlagsEntry  = "feature_flags.txt"
	maxFlagsBytes      = 64 << 10
)

// StudioFlags describes packaged defaults, not overrides in a running IDE.
type StudioFlags struct {
	Use1P  bool `json:"use_1p_login_ui"`
	UseFST bool `json:"enable_fsts"`
}

// InspectStudioPackage reads only the pinned distribution's feature flags.
// Its output is diagnostic evidence, never OAuth client configuration.
func InspectStudioPackage(commonJar string) (StudioFlags, error) {
	f, err := os.Open(commonJar)
	if err != nil {
		return StudioFlags{}, &Error{Code: "missing_artifact", Message: "could not open pinned android-common.jar"}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return StudioFlags{}, &Error{Code: "invalid_artifact", Message: "expected a small regular android-common.jar"}
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(f, 0, info.Size())); err != nil {
		return StudioFlags{}, &Error{Code: "invalid_artifact", Message: "could not hash android-common.jar"}
	}
	if hex.EncodeToString(hash.Sum(nil)) != pinnedCommonSHA256 {
		return StudioFlags{}, &Error{Code: "unpinned_artifact", Message: "android-common.jar SHA-256 does not match pinned Studio build"}
	}
	z, err := zip.NewReader(f, info.Size())
	if err != nil {
		return StudioFlags{}, &Error{Code: "invalid_artifact", Message: "failed opening android-common.jar archive"}
	}
	r, err := z.Open(featureFlagsEntry)
	if err != nil {
		return StudioFlags{}, &Error{Code: "incompatible_artifact", Message: "android-common.jar is missing feature_flags.txt"}
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, maxFlagsBytes+1))
	if err != nil || len(data) > maxFlagsBytes {
		return StudioFlags{}, &Error{Code: "invalid_artifact", Message: "unreadable or oversized Studio feature flags"}
	}
	actual := sha256.Sum256(data)
	if hex.EncodeToString(actual[:]) != pinnedFlagsSHA256 {
		return StudioFlags{}, &Error{Code: "unpinned_artifact", Message: "Studio feature flags SHA-256 mismatch"}
	}
	return stableStudioFlags(string(data))
}

// The feature configuration provider compares the Stable release level to
// each packaged flag's level. Higher-stability flags are enabled on more channels.
func stableStudioFlags(raw string) (StudioFlags, error) {
	var flags StudioFlags
	seen := make(map[string]bool, 2)
	for line := range strings.SplitSeq(raw, "\n") {
		name, value, ok := strings.Cut(strings.SplitN(line, "#", 2)[0], "=")
		name = strings.TrimSpace(name)
		if !ok || (name != use1PFlag && name != useFSTFlag) {
			continue
		}
		if seen[name] {
			return StudioFlags{}, &Error{Code: "incompatible_artifact", Message: "duplicate Studio OAuth feature flag"}
		}
		seen[name] = true
		level, _, _ := strings.Cut(strings.TrimSpace(value), ":")
		if level != "COMPLETE" && level != "PREVIEW" && level != "INTERNAL" {
			return StudioFlags{}, &Error{Code: "incompatible_artifact", Message: "unrecognized Studio OAuth feature rollout level"}
		}
		if name == use1PFlag {
			flags.Use1P = level == "COMPLETE"
		} else {
			flags.UseFST = level == "COMPLETE"
		}
	}
	if len(seen) != 2 {
		return StudioFlags{}, &Error{Code: "incompatible_artifact", Message: "missing packaged Studio OAuth feature flags"}
	}
	return flags, nil
}
