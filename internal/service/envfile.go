package service

import (
	"regexp"
	"sort"
	"strings"
)

// secretKeyRE matches the key names GitHub repository secrets accept and
// keeps sync consistent with the lander env endpoint.
var secretKeyRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// Secret is one env entry destined for a GitHub repository secret.
type Secret struct {
	Key   string
	Value string
}

// ParsedEnv is the result of reading a .env file. Skipped contains the names
// of entries that did not match the lander key rules; values are never
// included.
type ParsedEnv struct {
	Secrets []Secret
	Skipped []string
}

// ParseEnvFile reads dotenv-style content. It skips blank lines, comments,
// blank keys, invalid key names and entries with NUL bytes, accepts an
// optional "export " prefix, and keeps only the last value for duplicate keys.
func ParseEnvFile(data []byte) ParsedEnv {
	values := map[string]string{}
	var skipped []string

	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "export ")
		trimmed = strings.TrimSpace(trimmed)

		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			skipped = append(skipped, skipName(trimmed))
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			skipped = append(skipped, "<blank>")
			continue
		}
		if !secretKeyRE.MatchString(key) || strings.ContainsRune(value, 0) {
			skipped = append(skipped, key)
			continue
		}
		values[key] = unquote(strings.TrimSpace(value))
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

func unquote(value string) string {
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
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
