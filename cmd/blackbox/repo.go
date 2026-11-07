package main

import (
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
)

var repoPartRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// splitRepo validates an owner/name pair.
func splitRepo(value string) (string, string, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || !validRepoPart(parts[0]) || !validRepoPart(parts[1]) {
		return "", "", fmt.Errorf("repository must be owner/name, got %q", value)
	}
	return parts[0], parts[1], nil
}

func validRepoPart(part string) bool {
	return part != "" && part != "." && part != ".." && repoPartRE.MatchString(part)
}

// parseRepoURL extracts owner/name from common GitHub remote URLs.
func parseRepoURL(raw string) (string, string, error) {
	value := strings.TrimSpace(raw)
	value = strings.TrimSuffix(value, "/")
	value = strings.TrimSuffix(value, ".git")

	if strings.HasPrefix(value, "git@") {
		if _, path, ok := strings.Cut(strings.TrimPrefix(value, "git@"), ":"); ok {
			return splitRepo(path)
		}
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return "", "", fmt.Errorf("parse remote URL: %w", err)
		}
		return splitRepo(strings.TrimPrefix(parsed.Path, "/"))
	}

	return splitRepo(value)
}

// inferRepo reads the origin remote in the current git repository.
func inferRepo() (string, string, error) {
	out, err := exec.Command("git", "config", "--get", "remote.origin.url").Output()
	if err != nil {
		return "", "", fmt.Errorf("cannot infer repository from a git remote; pass --repo owner/name")
	}
	return parseRepoURL(string(out))
}
