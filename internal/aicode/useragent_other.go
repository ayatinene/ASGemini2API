//go:build !linux

package aicode

import "runtime"

func hostOSDetails() (osType, osVersion, arch string) {
	arch = runtime.GOARCH
	if arch == "arm64" {
		arch = "aarch64"
	}
	return runtime.GOOS, "unknown", arch
}
