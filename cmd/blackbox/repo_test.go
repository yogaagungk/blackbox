package main

import "testing"

func TestParseRepoURL(t *testing.T) {
	valid := map[string]string{
		"https://github.com/owner/repo.git":    "owner/repo",
		"https://github.com/owner/repo":        "owner/repo",
		"https://github.com/owner/repo/":       "owner/repo",
		"git@github.com:owner/repo.git":        "owner/repo",
		"ssh://git@github.com/owner/repo":      "owner/repo",
		"ssh://git@github.com/owner/repo.git/": "owner/repo",
		"owner/repo":                           "owner/repo",
	}
	for raw, want := range valid {
		owner, name, err := parseRepoURL(raw)
		if err != nil {
			t.Errorf("%q: %v", raw, err)
			continue
		}
		if owner+"/"+name != want {
			t.Errorf("%q = %s/%s, want %s", raw, owner, name, want)
		}
	}

	invalid := []string{
		"https://github.com/owner",
		"git@github.com:owner",
		"owner/repo/extra",
		"owner//repo",
		"../repo",
	}
	for _, raw := range invalid {
		if _, _, err := parseRepoURL(raw); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

func TestSplitRepoRejectsInvalidNames(t *testing.T) {
	for _, raw := range []string{"", "owner", "owner/", "/repo", "own er/repo"} {
		if _, _, err := splitRepo(raw); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}
