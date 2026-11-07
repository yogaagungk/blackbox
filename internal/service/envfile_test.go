package service

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
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

func TestParseEnvFileMultiLineQuotedValues(t *testing.T) {
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nline1\nline2\n-----END OPENSSH PRIVATE KEY-----\n"
	content := "DEPLOY_SSH_KEY=\"" + pem + "\"\nKNOWN_HOSTS='host1\nhost2'\n"
	parsed := ParseEnvFile([]byte(content))
	values := map[string]string{}
	for _, secret := range parsed.Secrets {
		values[secret.Key] = secret.Value
	}
	if values["DEPLOY_SSH_KEY"] != pem {
		t.Errorf("PEM = %q, want %q", values["DEPLOY_SSH_KEY"], pem)
	}
	if values["KNOWN_HOSTS"] != "host1\nhost2" {
		t.Errorf("KNOWN_HOSTS = %q", values["KNOWN_HOSTS"])
	}
	if len(parsed.Skipped) != 0 {
		t.Errorf("skipped = %v", parsed.Skipped)
	}
}

func TestParseEnvFileRejectsUnterminatedQuote(t *testing.T) {
	content := "GOOD=1\nBROKEN=\"-----BEGIN OPENSSH PRIVATE KEY-----\nline2\n"
	parsed := ParseEnvFile([]byte(content))
	if len(parsed.Secrets) != 1 || parsed.Secrets[0].Key != "GOOD" {
		t.Fatalf("secrets = %v", parsed.Secrets)
	}
	if !strings.Contains(strings.Join(parsed.Skipped, ","), "BROKEN") {
		t.Errorf("skipped = %v", parsed.Skipped)
	}
}

func TestParseEnvFileDoubleQuoteEscapes(t *testing.T) {
	parsed := ParseEnvFile([]byte(`A="line1\nline2\t\"quoted\"\\tail"` + "\n"))
	if len(parsed.Secrets) != 1 {
		t.Fatalf("secrets = %v", parsed.Secrets)
	}
	want := "line1\nline2\t\"quoted\"\\tail"
	if got := parsed.Secrets[0].Value; got != want {
		t.Errorf("value = %q, want %q", got, want)
	}
}

func TestMultiLineValueSealedRoundTrip(t *testing.T) {
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----\n"
	parsed := ParseEnvFile([]byte("DEPLOY_SSH_KEY=\"" + pem + "\"\n"))
	if len(parsed.Secrets) != 1 {
		t.Fatalf("secrets = %v", parsed.Secrets)
	}

	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(publicKey[:])
	sealed, err := SealSecret(encoded, []byte(parsed.Secrets[0].Value), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	opened, ok := box.OpenAnonymous(nil, ciphertext, publicKey, privateKey)
	if !ok {
		t.Fatal("sealed multi-line value did not decrypt")
	}
	if string(opened) != pem {
		t.Errorf("round-trip = %q, want %q", opened, pem)
	}
}

func TestPrepareSecrets(t *testing.T) {
	plan := PrepareSecrets(
		[]Secret{
			{Key: "FOO", Value: "1"},
			{Key: "GITHUB_TOKEN", Value: "reserved"},
			{Key: "LONG_VALUE", Value: strings.Repeat("x", MaxSecretValueBytes+1)},
			{Key: "DUP", Value: "old"},
		},
		[]Secret{{Key: "DUP", Value: "new"}, {Key: "BAR", Value: "2"}},
	)
	if len(plan.Secrets) != 3 {
		t.Fatalf("secrets = %+v", plan.Secrets)
	}
	if plan.Secrets[0].Key != "BAR" || plan.Secrets[1].Key != "DUP" || plan.Secrets[1].Value != "new" {
		t.Errorf("plan = %+v", plan.Secrets)
	}
	if plan.Secrets[2].Key != "FOO" {
		t.Errorf("plan = %+v", plan.Secrets)
	}
	skipped := strings.Join(plan.Skipped, ",")
	if !strings.Contains(skipped, "GITHUB_TOKEN") || !strings.Contains(skipped, "LONG_VALUE") {
		t.Errorf("skipped = %v", plan.Skipped)
	}
	if plan.OverLimit {
		t.Error("OverLimit should be false for 3 secrets")
	}
}
