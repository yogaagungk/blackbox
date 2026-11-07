package service

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// EnsureGitignore appends missing entries to path and reports what it added.
// Existing content and ordering are preserved.
func EnsureGitignore(path string, entries []string) ([]string, error) {
	// #nosec G304 -- repository-local .gitignore path.
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read .gitignore: %w", err)
	}

	existing := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		existing[strings.TrimSpace(line)] = true
	}

	var added []string
	for _, entry := range entries {
		if entry != "" && !existing[entry] {
			added = append(added, entry)
			existing[entry] = true
		}
	}
	if len(added) == 0 {
		return nil, nil
	}

	content := string(data)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += strings.Join(added, "\n") + "\n"
	if err := writeAtomic(path, []byte(content), 0o644); err != nil {
		return nil, fmt.Errorf("update .gitignore: %w", err)
	}
	return added, nil
}
