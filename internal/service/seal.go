package service

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// SealFile encrypts inPath to outPath for the age recipient. It streams
// through a temporary file and never prints plaintext. dryRun validates the
// inputs and returns the plaintext size without writing anything.
func SealFile(inPath, outPath, recipient string, dryRun bool) (int64, error) {
	if samePath(inPath, outPath) {
		return 0, fmt.Errorf("source and destination must differ")
	}
	pub, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return 0, fmt.Errorf("invalid recipient in config: %w", err)
	}
	info, err := os.Stat(inPath)
	if err != nil {
		return 0, fmt.Errorf("read source file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("source %s is not a regular file", inPath)
	}
	if dryRun {
		return info.Size(), nil
	}

	src, err := os.Open(inPath) // #nosec G304 -- CLI-provided source path.
	if err != nil {
		return 0, fmt.Errorf("open source file: %w", err)
	}
	defer func() { _ = src.Close() }()

	return writeStream(outPath, 0o644, func(dst io.Writer) (int64, error) {
		encrypted, err := age.Encrypt(dst, pub)
		if err != nil {
			return 0, fmt.Errorf("start encryption: %w", err)
		}
		copied, err := io.Copy(encrypted, src)
		if err != nil {
			_ = encrypted.Close()
			return 0, fmt.Errorf("encrypt: %w", err)
		}
		if err := encrypted.Close(); err != nil {
			return 0, fmt.Errorf("finish encryption: %w", err)
		}
		return copied, nil
	})
}

// UnsealFile decrypts inPath to outPath with the identity at keysPath.
// dryRun decrypts to io.Discard to prove the identity works without writing.
func UnsealFile(inPath, outPath, keysPath string, dryRun, force bool) (int64, error) {
	if samePath(inPath, outPath) {
		return 0, fmt.Errorf("source and destination must differ")
	}
	identity, err := LoadIdentity(keysPath)
	if err != nil {
		return 0, err
	}
	if !force {
		if _, err := os.Stat(outPath); err == nil {
			return 0, ErrDestinationExists
		} else if !os.IsNotExist(err) {
			return 0, fmt.Errorf("inspect destination: %w", err)
		}
	}

	src, err := os.Open(inPath) // #nosec G304 -- CLI-provided source path.
	if err != nil {
		return 0, fmt.Errorf("open source file: %w", err)
	}
	defer func() { _ = src.Close() }()

	if dryRun {
		decrypted, err := age.Decrypt(src, identity)
		if err != nil {
			return 0, fmt.Errorf("decrypt: %w", err)
		}
		copied, err := io.Copy(io.Discard, decrypted)
		if err != nil {
			return 0, fmt.Errorf("decrypt: %w", err)
		}
		return copied, nil
	}

	return writeStream(outPath, 0o600, func(dst io.Writer) (int64, error) {
		decrypted, err := age.Decrypt(src, identity)
		if err != nil {
			return 0, fmt.Errorf("decrypt: %w", err)
		}
		copied, err := io.Copy(dst, decrypted)
		if err != nil {
			return 0, fmt.Errorf("decrypt: %w", err)
		}
		return copied, nil
	})
}

// writeStream writes a temp file in the destination directory, runs fill and
// atomically renames the result into place.
func writeStream(path string, mode os.FileMode, fill func(io.Writer) (int64, error)) (int64, error) {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	name := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(name)
	}
	if err := temp.Chmod(mode); err != nil {
		cleanup()
		return 0, fmt.Errorf("set file mode: %w", err)
	}
	written, err := fill(temp)
	if err != nil {
		cleanup()
		return 0, err
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return 0, fmt.Errorf("sync temp file: %w", err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(name)
		return 0, fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return 0, fmt.Errorf("install file: %w", err)
	}
	return written, nil
}

func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return absA == absB
}
