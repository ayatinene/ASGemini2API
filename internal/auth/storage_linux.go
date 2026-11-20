//go:build linux

package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func openPrivateClientFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0o077 != 0 {
		_ = f.Close()
		return nil, os.ErrPermission
	}
	return f, nil
}

type fileIdentity struct {
	dev     uint64
	ino     uint64
	mtimeNS int64
	size    int64
}

func sameIdentity(a, b fileIdentity) bool {
	return a.dev == b.dev && a.ino == b.ino && a.mtimeNS == b.mtimeNS && a.size == b.size
}

func identityFromStat(st *syscall.Stat_t) fileIdentity {
	return fileIdentity{
		dev:     st.Dev,
		ino:     st.Ino,
		mtimeNS: st.Mtim.Sec*1_000_000_000 + st.Mtim.Nsec,
		size:    st.Size,
	}
}

func openStateDirFD(stateDir string, create bool, enforceMode bool) (int, error) {
	info, err := os.Lstat(stateDir)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return -1, &Error{Code: "insecure_storage", Message: "refusing symlink in credential storage path"}
		}
	} else if os.IsNotExist(err) {
		if !create {
			return -1, nil
		}
		if mkErr := os.MkdirAll(stateDir, 0o700); mkErr != nil {
			return -1, &Error{Code: "insecure_storage", Message: "cannot create auth state directory"}
		}
		if chErr := os.Chmod(stateDir, 0o700); chErr != nil {
			return -1, &Error{Code: "insecure_storage", Message: "cannot set permissions on auth state directory"}
		}
	} else {
		return -1, &Error{Code: "insecure_storage", Message: "cannot inspect auth state directory"}
	}

	fd, err := syscall.Open(stateDir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if !create && errors.Is(err, syscall.ENOENT) {
			return -1, nil
		}
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			return -1, &Error{Code: "insecure_storage", Message: "auth state_dir must be a real directory, not a symlink"}
		}
		return -1, &Error{Code: "insecure_storage", Message: "cannot open auth state directory safely"}
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return -1, &Error{Code: "insecure_storage", Message: "cannot stat auth state directory"}
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		_ = syscall.Close(fd)
		return -1, &Error{Code: "insecure_storage", Message: "auth state_dir is not a directory"}
	}
	if st.Uid != uint32(os.Geteuid()) {
		_ = syscall.Close(fd)
		return -1, &Error{Code: "insecure_storage", Message: "auth state_dir is not owned by current user"}
	}
	if enforceMode && (st.Mode&0o077) != 0 {
		_ = syscall.Close(fd)
		return -1, &Error{Code: "insecure_storage", Message: "auth state_dir permissions must be owner-only (0700)"}
	}
	return fd, nil
}

func openRegularStateFileNoFollow(dirFD int) (int, syscall.Stat_t, error) {
	var fst syscall.Stat_t
	fd, err := syscall.Openat(dirFD, stateFilename, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return -1, fst, nil
		}
		if errors.Is(err, syscall.ELOOP) {
			return -1, fst, &Error{Code: "insecure_storage", Message: "refusing symlink in credential storage path"}
		}
		return -1, fst, &Error{Code: "insecure_storage", Message: "cannot open auth state file safely"}
	}
	if err := syscall.Fstat(fd, &fst); err != nil {
		_ = syscall.Close(fd)
		return -1, fst, &Error{Code: "insecure_storage", Message: "cannot stat auth state file"}
	}
	if fst.Mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = syscall.Close(fd)
		return -1, fst, &Error{Code: "insecure_storage", Message: "auth state path must be a regular file"}
	}
	return fd, fst, nil
}

func readPersistedRaw(stateDir string) ([]byte, *fileIdentity, error) {
	dirFD, err := openStateDirFD(stateDir, false, true)
	if err != nil {
		return nil, nil, err
	}
	if dirFD < 0 {
		return nil, nil, nil
	}
	defer func() { _ = syscall.Close(dirFD) }()

	fd, fst, err := openRegularStateFileNoFollow(dirFD)
	if err != nil || fd < 0 {
		return nil, nil, err
	}
	defer func() { _ = syscall.Close(fd) }()

	if fst.Uid != uint32(os.Geteuid()) {
		return nil, nil, &Error{Code: "insecure_storage", Message: "auth state file is not owned by current user"}
	}
	if (fst.Mode & 0o077) != 0 {
		return nil, nil, &Error{Code: "insecure_storage", Message: "auth state file permissions must be 0600 or stricter"}
	}
	if fst.Size > maxHTTPBodyBytes {
		return nil, nil, &Error{Code: "corrupt_state", Message: "auth state file exceeds maximum size"}
	}

	buf := make([]byte, 0, fst.Size+1)
	chunk := make([]byte, 32*1024)
	for {
		n, rerr := syscall.Read(fd, chunk)
		if n > 0 {
			if len(buf)+n > maxHTTPBodyBytes {
				return nil, nil, &Error{Code: "corrupt_state", Message: "auth state file exceeds maximum size"}
			}
			buf = append(buf, chunk[:n]...)
		}
		if rerr != nil {
			if errors.Is(rerr, syscall.EINTR) {
				continue
			}
			return nil, nil, &Error{Code: "corrupt_state", Message: "failed reading auth state file"}
		}
		if n == 0 {
			break
		}
	}
	id := identityFromStat(&fst)
	return buf, &id, nil
}

func writePersistedRaw(stateDir string, encoded []byte) (fileIdentity, error) {
	dirFD, err := openStateDirFD(stateDir, true, true)
	if err != nil {
		return fileIdentity{}, err
	}
	defer func() { _ = syscall.Close(dirFD) }()

	existingFD, _, err := openRegularStateFileNoFollow(dirFD)
	if err != nil {
		return fileIdentity{}, err
	}
	if existingFD >= 0 {
		_ = syscall.Close(existingFD)
	}

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fileIdentity{}, &Error{Code: "insecure_storage", Message: "cannot allocate temporary state filename"}
	}
	tmpName := fmt.Sprintf(".%s.%s.tmp", stateFilename, hex.EncodeToString(rnd[:]))

	fd, err := syscall.Openat(dirFD, tmpName, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fileIdentity{}, &Error{Code: "insecure_storage", Message: "cannot create temporary auth state file"}
	}

	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = syscall.Unlinkat(dirFD, tmpName)
		}
	}()

	if err := syscall.Fchmod(fd, 0o600); err != nil {
		_ = syscall.Close(fd)
		return fileIdentity{}, &Error{Code: "insecure_storage", Message: "cannot set 0600 permissions on auth state file"}
	}

	written := 0
	for written < len(encoded) {
		n, werr := syscall.Write(fd, encoded[written:])
		if n > 0 {
			written += n
		}
		if werr != nil {
			if errors.Is(werr, syscall.EINTR) {
				continue
			}
			_ = syscall.Close(fd)
			return fileIdentity{}, &Error{Code: "insecure_storage", Message: "failed writing auth state file"}
		}
	}
	if err := syscall.Fsync(fd); err != nil {
		_ = syscall.Close(fd)
		return fileIdentity{}, &Error{Code: "insecure_storage", Message: "failed syncing auth state file"}
	}

	var fst syscall.Stat_t
	if err := syscall.Fstat(fd, &fst); err != nil {
		_ = syscall.Close(fd)
		return fileIdentity{}, &Error{Code: "insecure_storage", Message: "failed stating auth state file"}
	}
	if err := syscall.Close(fd); err != nil {
		return fileIdentity{}, &Error{Code: "insecure_storage", Message: "failed closing auth state file"}
	}

	if err := syscall.Renameat(dirFD, tmpName, dirFD, stateFilename); err != nil {
		return fileIdentity{}, &Error{Code: "insecure_storage", Message: "failed replacing auth state file atomically"}
	}
	cleanupTmp = false
	_ = syscall.Fsync(dirFD)
	return identityFromStat(&fst), nil
}

func unlinkPersistedState(stateDir string) (bool, error) {
	if info, err := os.Lstat(filepath.Clean(stateDir)); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return false, &Error{Code: "insecure_storage", Message: "refusing symlink in credential storage path"}
	}
	dirFD, err := openStateDirFD(stateDir, false, false)
	if err != nil {
		return false, err
	}
	if dirFD < 0 {
		return false, nil
	}
	defer func() { _ = syscall.Close(dirFD) }()

	fd, _, err := openRegularStateFileNoFollow(dirFD)
	if err != nil {
		return false, err
	}
	if fd < 0 {
		return false, nil
	}
	_ = syscall.Close(fd)

	if err := syscall.Unlinkat(dirFD, stateFilename); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return false, nil
		}
		return false, &Error{Code: "insecure_storage", Message: "failed removing auth state file"}
	}
	return true, nil
}
