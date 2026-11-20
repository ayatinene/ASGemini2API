//go:build linux

package aicode

import (
	"bytes"

	"golang.org/x/sys/unix"
)

func hostOSDetails() (osType, osVersion, arch string) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "Linux", "unknown", "aarch64"
	}
	sysname := cString(uts.Sysname[:])
	release := cString(uts.Release[:])
	machine := cString(uts.Machine[:])
	if sysname == "" {
		sysname = "Linux"
	}
	if release == "" {
		release = "unknown"
	}
	if machine == "" {
		machine = "aarch64"
	}
	return sysname, release, machine
}

func cString(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx >= 0 {
		b = b[:idx]
	}
	return string(b)
}
