package responder

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// EndpointConfig represents a single command endpoint loaded from endpoints.yaml.
type EndpointConfig struct {
	Name     string
	Link     string
	ArgRegex string
	compiled *regexp.Regexp
}

// Compiled returns the compiled arg_regex, or nil if none was specified.
func (e *EndpointConfig) Compiled() *regexp.Regexp {
	return e.compiled
}

// Compile compiles ArgRegex and stores it on the endpoint.
// Called automatically by LoadConfigFrom; exposed so tests can build
// EndpointConfig values directly without going through a YAML file.
func (e *EndpointConfig) Compile() error {
	if e.ArgRegex == "" {
		return nil
	}
	re, err := regexp.Compile(e.ArgRegex)
	if err != nil {
		return err
	}
	e.compiled = re
	return nil
}

// Config holds all endpoint configurations loaded from endpoints.yaml.
type Config struct {
	Commands []EndpointConfig
}

// EndpointByName looks up a command by name.
func (c *Config) EndpointByName(name string) (*EndpointConfig, bool) {
	for i := range c.Commands {
		if c.Commands[i].Name == name {
			return &c.Commands[i], true
		}
	}
	return nil, false
}

// CommandList returns a human-readable listing of all available commands.
func (c *Config) CommandList() string {
	var sb strings.Builder
	for _, cmd := range c.Commands {
		sb.WriteString(fmt.Sprintf("  %s → %s\n", cmd.Name, cmd.Link))
		if cmd.ArgRegex != "" {
			sb.WriteString(fmt.Sprintf("    body format (regex): %s\n", cmd.ArgRegex))
		}
	}
	return sb.String()
}

// DefaultConfigPath returns ~/.pilot/endpoints.yaml.
func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".pilot", "endpoints.yaml"), nil
}

// LoadConfig loads and validates endpoints.yaml from the default path.
func LoadConfig() (*Config, error) {
	path, err := DefaultConfigPath()
	if err != nil {
		return nil, err
	}
	return LoadConfigFrom(path)
}

// LoadConfigFrom loads and validates endpoints.yaml from a specific path.
// Returns an error (and exits-worthy message) if the file is missing, malformed,
// or contains no commands — responder cannot start without a valid config.
func LoadConfigFrom(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("endpoints.yaml not found at %s\nresponder cannot start without a valid endpoints.yaml", path)
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	cfg, err := ParseEndpointsYAML(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(cfg.Commands) == 0 {
		return nil, fmt.Errorf("%s has no commands defined", path)
	}

	// Compile and validate regexes eagerly so startup fails fast on bad config.
	for i := range cfg.Commands {
		ep := &cfg.Commands[i]
		if ep.Name == "" {
			return nil, fmt.Errorf("command at index %d has no name", i)
		}
		if ep.Link == "" {
			return nil, fmt.Errorf("command %q has no link", ep.Name)
		}
		if ep.ArgRegex == "" {
			continue
		}
		re, err := regexp.Compile(ep.ArgRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid arg_regex for command %q: %w", ep.Name, err)
		}
		ep.compiled = re
	}
	return cfg, nil
}

// ParseEndpointsYAML parses the specific endpoints.yaml structure without external deps.
//
// Expected format:
//
//	commands:
//	  - name: <string>
//	    link: <url>
//	    arg_regex: <regex>   # optional
func ParseEndpointsYAML(r io.Reader) (*Config, error) {
	scanner := bufio.NewScanner(r)
	cfg := &Config{}
	inCommands := false
	var cur *EndpointConfig

	flush := func() {
		if cur != nil && cur.Name != "" {
			cfg.Commands = append(cfg.Commands, *cur)
			cur = nil
		}
	}

	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)

		// Skip blank lines and comments.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := countLeadingSpaces(raw)

		switch {
		case indent == 0 && trimmed == "commands:":
			inCommands = true

		case !inCommands:
			// Ignore unrecognised top-level keys.

		case indent == 2 && strings.HasPrefix(trimmed, "- "):
			// Start of a new list item.
			flush()
			cur = &EndpointConfig{}
			rest := trimmed[2:] // strip leading "- "
			k, v := SplitKV(rest)
			applyField(cur, k, v)

		case cur != nil && indent >= 4:
			// Field belonging to the current list item.
			k, v := SplitKV(trimmed)
			applyField(cur, k, v)
		}
	}
	flush()

	return cfg, scanner.Err()
}

func applyField(cmd *EndpointConfig, key, val string) {
	switch key {
	case "name":
		cmd.Name = val
	case "link":
		cmd.Link = val
	case "arg_regex":
		cmd.ArgRegex = val
	}
}

// SplitKV splits "key: value" into ("key", "value"), handling YAML quoting.
// Double-quoted values: processes \\ → \ and \" → " escape sequences (YAML spec).
// Single-quoted values: content is verbatim (no escapes in YAML single-quoted strings).
// Unquoted values: trailing inline comments (` #...`) are stripped.
func SplitKV(s string) (string, string) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return strings.TrimSpace(s), ""
	}
	key := strings.TrimSpace(s[:idx])
	val := strings.TrimSpace(s[idx+1:])

	if len(val) == 0 {
		return key, val
	}

	switch {
	case len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"':
		val = unescapeDoubleQuoted(val[1 : len(val)-1])
	case len(val) >= 2 && val[0] == '\'' && val[len(val)-1] == '\'':
		val = val[1 : len(val)-1]
	default:
		if ci := strings.Index(val, " #"); ci >= 0 {
			val = strings.TrimSpace(val[:ci])
		}
	}
	return key, val
}

// unescapeDoubleQuoted processes YAML double-quoted escape sequences in s
// (outer quotes must be stripped before calling).
// Handles: \\ → \  and  \" → "  which covers regex patterns and URLs.
func unescapeDoubleQuoted(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\':
				b.WriteByte('\\')
				i += 2
				continue
			case '"':
				b.WriteByte('"')
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// countLeadingSpaces counts the number of leading space characters in s.
func countLeadingSpaces(s string) int {
	n := 0
	for _, c := range s {
		if c == ' ' {
			n++
		} else {
			break
		}
	}
	return n
}
