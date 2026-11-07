package service

import (
	"strings"
	"testing"
)

func TestParseEnvFile(t *testing.T) {
	content := strings.Join([]string{
		"# comment",
		"",
		"export API_KEY=abc",
		"lower=no",
		"BAD KEY=x",
		"QUOTED=\"hello world\"",
		"SINGLE='one two'",
		"BLANK=   ",
		"DUP=one",
		"DUP=two",
		"NOEQUALS",
		"WITH_NUL=bad\x00value",
	}, "\n")

	parsed := ParseEnvFile([]byte(content))
	values := map[string]string{}
	for _, secret := range parsed.Secrets {
		values[secret.Key] = secret.Value
	}
	if len(values) != 5 {
		t.Fatalf("secrets = %v", values)
	}
	if values["API_KEY"] != "abc" || values["QUOTED"] != "hello world" || values["SINGLE"] != "one two" {
		t.Errorf("values = %v", values)
	}
	if values["BLANK"] != "" {
		t.Errorf("BLANK = %q, want empty", values["BLANK"])
	}
	if values["DUP"] != "two" {
		t.Errorf("DUP = %q, want the last value", values["DUP"])
	}

	skipped := strings.Join(parsed.Skipped, ",")
	for _, want := range []string{"lower", "BAD KEY", "NOEQUALS", "WITH_NUL"} {
		if !strings.Contains(skipped, want) {
			t.Errorf("skipped %q missing %q", skipped, want)
		}
	}
	if strings.Contains(skipped, "abc") || strings.Contains(skipped, "hello") {
		t.Errorf("skipped entries leaked values: %q", skipped)
	}
}

func TestParseEnvFileSortsKeys(t *testing.T) {
	parsed := ParseEnvFile([]byte("B=2\nA=1\nC=3\n"))
	keys := make([]string, 0, len(parsed.Secrets))
	for _, secret := range parsed.Secrets {
		keys = append(keys, secret.Key)
	}
	if strings.Join(keys, ",") != "A,B,C" {
		t.Errorf("keys = %v", keys)
	}
}

func TestParseEnvFileExcludesBlankKeys(t *testing.T) {
	parsed := ParseEnvFile([]byte("=no-key\nA=1\n"))
	if len(parsed.Secrets) != 1 || parsed.Secrets[0].Key != "A" {
		t.Errorf("secrets = %v", parsed.Secrets)
	}
	if !strings.Contains(strings.Join(parsed.Skipped, ","), "<blank>") {
		t.Errorf("skipped = %v", parsed.Skipped)
	}
}
