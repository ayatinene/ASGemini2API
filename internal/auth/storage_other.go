//go:build !linux

package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func openPrivateClientFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, os.ErrPermission
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	current, err := f.Stat()
	if err != nil || !os.SameFile(info, current) || current.Mode().Perm()&0o077 != 0 {
		_ = f.Close()
		return nil, os.ErrPermission
	}
	return f, nil
}

type fileIdentity struct {
	mtimeNS int64
	size    int64
}

func sameIdentity(a, b fileIdentity) bool {
	return a.mtimeNS == b.mtimeNS && a.size == b.size
}

func openStateRoot(stateDir string, create bool, enforceMode bool) (*os.Root, error) {
	info, err := os.Lstat(stateDir)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, &Error{Code: "insecure_storage", Message: "refusing symlink in credential storage path"}
		}
		if !info.IsDir() {
			return nil, &Error{Code: "insecure_storage", Message: "auth state_dir is not a directory"}
		}
		if enforceMode && (info.Mode().Perm()&0o077) != 0 {
			return nil, &Error{Code: "insecure_storage", Message: "auth state_dir permissions must be owner-only (0700)"}
		}
	} else if os.IsNotExist(err) {
		if !create {
			return nil, nil
		}
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return nil, &Error{Code: "insecure_storage", Message: "cannot create auth state directory"}
		}
		if err := os.Chmod(stateDir, 0o700); err != nil {
			return nil, &Error{Code: "insecure_storage", Message: "cannot set permissions on auth state directory"}
		}
	} else {
		return nil, &Error{Code: "insecure_storage", Message: "cannot inspect auth state directory"}
	}

	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return nil, &Error{Code: "insecure_storage", Message: "cannot open auth state directory"}
	}
	return root, nil
}

func readPersistedRaw(stateDir string) ([]byte, *fileIdentity, error) {
	root, err := openStateRoot(stateDir, false, true)
	if err != nil {
		return nil, nil, err
	}
	if root == nil {
		return nil, nil, nil
	}
	defer func() { _ = root.Close() }()

	info, err := root.Lstat(stateFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, &Error{Code: "insecure_storage", Message: "cannot inspect auth state file"}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, nil, &Error{Code: "insecure_storage", Message: "auth state path must be a regular file"}
	}
	if (info.Mode().Perm() & 0o077) != 0 {
		return nil, nil, &Error{Code: "insecure_storage", Message: "auth state file permissions must be 0600 or stricter"}
	}

	f, err := root.Open(stateFilename)
	if err != nil {
		return nil, nil, &Error{Code: "insecure_storage", Message: "cannot open auth state file"}
	}
	defer func() { _ = f.Close() }()

	finfo, err := f.Stat()
	if err != nil || !finfo.Mode().IsRegular() || (finfo.Mode().Perm()&0o077) != 0 {
		return nil, nil, &Error{Code: "insecure_storage", Message: "auth state file permissions must be 0600 or stricter"}
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxHTTPBodyBytes+1))
	if err != nil {
		return nil, nil, &Error{Code: "corrupt_state", Message: "failed reading auth state file"}
	}
	if len(raw) > maxHTTPBodyBytes {
		return nil, nil, &Error{Code: "corrupt_state", Message: "auth state file exceeds maximum size"}
	}
	id := fileIdentity{mtimeNS: finfo.ModTime().UnixNano(), size: finfo.Size()}
	return raw, &id, nil
}

func writePersistedRaw(stateDir string, encoded []byte) (fileIdentity, error) {
	root, err := openStateRoot(stateDir, true, true)
	if err != nil {
		return fileIdentity{}, err
	}
	defer func() { _ = root.Close() }()

	if info, err := root.Lstat(stateFilename); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fileIdentity{}, &Error{Code: "insecure_storage", Message: "refusing non-regular auth state target"}
		}
	}

	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmpName := fmt.Sprintf(".%s.%s.tmp", stateFilename, hex.EncodeToString(rnd[:]))
	f, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fileIdentity{}, &Error{Code: "insecure_storage", Message: "cannot create temporary auth state file"}
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		_ = root.Remove(tmpName)
		return fileIdentity{}, &Error{Code: "insecure_storage", Message: "failed writing auth state file"}
	}
	_ = f.Sync()
	info, statErr := f.Stat()
	_ = f.Close()
	if statErr != nil {
		_ = root.Remove(tmpName)
		return fileIdentity{}, &Error{Code: "insecure_storage", Message: "failed stating auth state file"}
	}
	if err := root.Rename(tmpName, stateFilename); err != nil {
		_ = root.Remove(tmpName)
		return fileIdentity{}, &Error{Code: "insecure_storage", Message: "failed replacing auth state file"}
	}
	return fileIdentity{mtimeNS: info.ModTime().UnixNano(), size: info.Size()}, nil
}

func unlinkPersistedState(stateDir string) (bool, error) {
	if info, err := os.Lstat(filepath.Clean(stateDir)); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return false, &Error{Code: "insecure_storage", Message: "refusing symlink in credential storage path"}
	}
	root, err := openStateRoot(stateDir, false, false)
	if err != nil {
		return false, err
	}
	if root == nil {
		return false, nil
	}
	defer func() { _ = root.Close() }()

	info, err := root.Lstat(stateFilename)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, &Error{Code: "insecure_storage", Message: "cannot inspect auth state file"}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, &Error{Code: "insecure_storage", Message: "refusing to unlink non-regular auth state file"}
	}
	if err := root.Remove(stateFilename); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, &Error{Code: "insecure_storage", Message: "failed removing auth state file"}
	}
	return true, nil
}
