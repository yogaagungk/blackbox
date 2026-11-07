package service

import (
	"regexp"
	"sort"
	"strings"
)

// secretKeyRE matches the key names GitHub repository secrets accept and
// keeps sync consistent with the lander env endpoint.
var secretKeyRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

const (
	// MaxSecretValueBytes is GitHub's limit for one secret value.
	MaxSecretValueBytes = 48 * 1024
	// MaxRepoSecrets is the GitHub limit per repository.
	MaxRepoSecrets = 100
)

// Secret is one env entry destined for a GitHub repository secret.
type Secret struct {
	Key   string
	Value string
}

// ParsedEnv is the result of reading a .env file. Skipped contains the names
// of entries that were not usable; values are never included.
type ParsedEnv struct {
	Secrets []Secret
	Skipped []string
}

// SecretPlan is the pre-filtered upload set.
type SecretPlan struct {
	Secrets   []Secret
	Skipped   []string
	OverLimit bool
}

// IsValidSecretKey reports whether key is an accepted secret name.
func IsValidSecretKey(key string) bool {
	return secretKeyRE.MatchString(key)
}

// ParseEnvFile reads dotenv-style content. It supports single- and
// double-quoted values spanning multiple lines, rejects unterminated quotes,
// interprets \n, \t, \r, \" and \\ inside double quotes, and skips blank
// lines, comments, blank keys and invalid key names. Inline `#` comments are
// not stripped. Duplicate keys keep the last value.
func ParseEnvFile(data []byte) ParsedEnv {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	values := map[string]string{}
	var skipped []string

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))

		key, rest, ok := strings.Cut(line, "=")
		if !ok {
			skipped = append(skipped, skipName(line))
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			skipped = append(skipped, "<blank>")
			continue
		}

		value, extraLines, valueOK := parseValue(rest, lines[i+1:])
		i += extraLines
		if !valueOK || !secretKeyRE.MatchString(key) || strings.ContainsRune(value, 0) {
			skipped = append(skipped, key)
			continue
		}
		values[key] = value
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parsed := ParsedEnv{Skipped: skipped}
	for _, key := range keys {
		parsed.Secrets = append(parsed.Secrets, Secret{Key: key, Value: values[key]})
	}
	return parsed
}

// parseValue returns the decoded value and how many following lines it
// consumed. A quoted value with no closing quote is rejected (ok=false) so a
// truncated multi-line secret can never be uploaded.
func parseValue(rest string, following []string) (value string, extraLines int, ok bool) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", 0, true
	}
	if rest[0] != '"' && rest[0] != '\'' {
		// Inline # comments are intentionally part of the value.
		return rest, 0, true
	}

	quote := rest[0]
	current := rest[1:]
	var buf strings.Builder
	for {
		for i := 0; i < len(current); i++ {
			c := current[i]
			if quote == '"' && c == '\\' {
				if i+1 >= len(current) {
					buf.WriteByte(c)
					continue
				}
				writeDoubleQuoteEscape(&buf, current[i+1])
				i++
				continue
			}
			if c == quote {
				tail := strings.TrimSpace(current[i+1:])
				if tail != "" && !strings.HasPrefix(tail, "#") {
					return "", extraLines, false
				}
				return buf.String(), extraLines, true
			}
			buf.WriteByte(c)
		}

		// No closing quote yet: standard dotenv continues on the next line.
		extraLines++
		if extraLines > len(following) {
			return "", extraLines - 1, false
		}
		buf.WriteByte('\n')
		current = following[extraLines-1]
	}
}

func writeDoubleQuoteEscape(buf *strings.Builder, c byte) {
	switch c {
	case 'n':
		buf.WriteByte('\n')
	case 't':
		buf.WriteByte('\t')
	case 'r':
		buf.WriteByte('\r')
	case '"':
		buf.WriteByte('"')
	case '\\':
		buf.WriteByte('\\')
	default:
		// Keep unknown escapes intact rather than silently dropping them.
		buf.WriteByte('\\')
		buf.WriteByte(c)
	}
}

// PrepareSecrets merges base entries with overrides, removes names GitHub
// reserves or values it will reject, and returns a sorted upload plan.
func PrepareSecrets(base, overrides []Secret) SecretPlan {
	merged := map[string]string{}
	for _, secret := range base {
		merged[secret.Key] = secret.Value
	}
	for _, secret := range overrides {
		merged[secret.Key] = secret.Value
	}

	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	plan := SecretPlan{}
	for _, key := range keys {
		value := merged[key]
		switch {
		case strings.HasPrefix(key, "GITHUB_"):
			plan.Skipped = append(plan.Skipped, key+" (reserved GITHUB_ prefix)")
			continue
		case len(value) > MaxSecretValueBytes:
			plan.Skipped = append(plan.Skipped, key+" (value exceeds 48 KiB)")
			continue
		}
		plan.Secrets = append(plan.Secrets, Secret{Key: key, Value: value})
	}
	plan.OverLimit = len(plan.Secrets) > MaxRepoSecrets
	return plan
}

// skipName keeps warning output short and free of values.
func skipName(line string) string {
	if idx := strings.IndexByte(line, '='); idx > 0 {
		return strings.TrimSpace(line[:idx])
	}
	if len(line) > 32 {
		return line[:32] + "..."
	}
	return line
}
