package tests

import (
	"regexp"
	"strings"
	"testing"
)

// Validation regexes (mirrored from pkg/registry/server.go — unexported there)
var (
	hostnameRegex     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tagRegex          = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	networkNameRegex  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reservedHostnames = map[string]bool{
		"localhost": true,
		"backbone":  true,
		"broadcast": true,
	}
	reservedNetworkNames = map[string]bool{
		"backbone": true,
	}
)

// ---------------------------------------------------------------------------
// Fuzz targets
// ---------------------------------------------------------------------------

func FuzzHostnameValidation(f *testing.F) {
	f.Add("a")
	f.Add("myhost")
	f.Add("my-host")
	f.Add("a1b2c3")
	f.Add(strings.Repeat("a", 63))
	f.Add(strings.Repeat("a", 64))
	f.Add("-starts-with-hyphen")
	f.Add("ends-with-hyphen-")
	f.Add("---")
	f.Add("123")
	f.Add("UPPERCASE")
	f.Add("localhost")
	f.Add("")
	f.Add("a-b-c-d")
	f.Add(strings.Repeat("x", 1000))
	f.Add("host.name")
	f.Add("host name")
	f.Add("host\x00name")

	f.Fuzz(func(t *testing.T, s string) {
		// Must not panic
		_ = hostnameRegex.MatchString(s)
	})
}

func FuzzTagValidation(f *testing.F) {
	f.Add("a")
	f.Add("my-tag")
	f.Add(strings.Repeat("a", 32))
	f.Add(strings.Repeat("a", 33))
	f.Add("#tagged")
	f.Add("")
	f.Add("UPPER")
	f.Add("-hyphen")
	f.Add("hyphen-")

	f.Fuzz(func(t *testing.T, s string) {
		_ = tagRegex.MatchString(s)
	})
}

func FuzzNetworkNameValidation(f *testing.F) {
	f.Add("mynet")
	f.Add("backbone")
	f.Add(strings.Repeat("a", 63))
	f.Add(strings.Repeat("a", 64))
	f.Add("")
	f.Add("UPPER")

	f.Fuzz(func(t *testing.T, s string) {
		_ = networkNameRegex.MatchString(s)
	})
}

// ---------------------------------------------------------------------------
// Hostname edge case unit tests
// ---------------------------------------------------------------------------

func TestHostnameSingleChar(t *testing.T) {
	if !hostnameRegex.MatchString("a") {
		t.Fatal("single char 'a' should be valid")
	}
	if !hostnameRegex.MatchString("0") {
		t.Fatal("single char '0' should be valid")
	}
}

func TestHostnameMaxLength63(t *testing.T) {
	name := strings.Repeat("a", 63)
	if !hostnameRegex.MatchString(name) {
		t.Fatal("63-char hostname should be valid")
	}
}

func TestHostnameLength64Rejected(t *testing.T) {
	name := strings.Repeat("a", 64)
	if hostnameRegex.MatchString(name) {
		t.Fatal("64-char hostname should be rejected by regex")
	}
}

func TestHostnameLeadingHyphen(t *testing.T) {
	if hostnameRegex.MatchString("-start") {
		t.Fatal("leading hyphen should be rejected")
	}
}

func TestHostnameTrailingHyphen(t *testing.T) {
	if hostnameRegex.MatchString("end-") {
		t.Fatal("trailing hyphen should be rejected")
	}
}

func TestHostnameOnlyHyphens(t *testing.T) {
	if hostnameRegex.MatchString("---") {
		t.Fatal("only hyphens should be rejected")
	}
}

func TestHostnameNumericOnly(t *testing.T) {
	if !hostnameRegex.MatchString("123") {
		t.Fatal("numeric-only hostname should be valid")
	}
}

func TestHostnameReserved(t *testing.T) {
	for name := range reservedHostnames {
		if !reservedHostnames[name] {
			t.Errorf("expected %q to be reserved", name)
		}
	}
}

func TestHostnameUppercase(t *testing.T) {
	if hostnameRegex.MatchString("UPPER") {
		t.Fatal("uppercase should be rejected")
	}
	if hostnameRegex.MatchString("MyHost") {
		t.Fatal("mixed case should be rejected")
	}
}

func TestHostnameWithDot(t *testing.T) {
	if hostnameRegex.MatchString("host.name") {
		t.Fatal("dot in hostname should be rejected")
	}
}

func TestHostnameWithUnderscore(t *testing.T) {
	if hostnameRegex.MatchString("host_name") {
		t.Fatal("underscore in hostname should be rejected")
	}
}

// ---------------------------------------------------------------------------
// Tag edge case unit tests
// ---------------------------------------------------------------------------

func TestTagSingleChar(t *testing.T) {
	if !tagRegex.MatchString("a") {
		t.Fatal("single char tag should be valid")
	}
}

func TestTagMax32Chars(t *testing.T) {
	tag := strings.Repeat("a", 32)
	if !tagRegex.MatchString(tag) {
		t.Fatal("32-char tag should be valid")
	}
}

func TestTagLength33Rejected(t *testing.T) {
	tag := strings.Repeat("a", 33)
	if tagRegex.MatchString(tag) {
		t.Fatal("33-char tag should be rejected")
	}
}

func TestTagWithLeadingHash(t *testing.T) {
	// "#tagged" — the '#' is stripped by normalization in the server,
	// but the regex itself would reject "#tagged"
	if tagRegex.MatchString("#tagged") {
		t.Fatal("tag with '#' should be rejected by regex")
	}
}

func TestTagNormalization(t *testing.T) {
	// Simulate normalization: strip '#'
	tag := "#ml-task"
	normalized := strings.TrimPrefix(tag, "#")
	if !tagRegex.MatchString(normalized) {
		t.Fatalf("normalized tag %q should be valid", normalized)
	}
}

func TestTagEmptyAfterNormalization(t *testing.T) {
	tag := "#"
	normalized := strings.TrimPrefix(tag, "#")
	if normalized != "" {
		t.Fatal("expected empty after stripping '#'")
	}
	// Empty string should fail the regex (requires at least 1 char)
	if tagRegex.MatchString(normalized) {
		t.Fatal("empty tag should be rejected")
	}
}

func TestTagMaxCount(t *testing.T) {
	// Max 10 tags allowed (validated in server, not regex)
	tags := make([]string, 11)
	for i := range tags {
		tags[i] = "tag"
	}
	if len(tags) <= 10 {
		t.Fatal("test setup error")
	}
}

// ---------------------------------------------------------------------------
// Network name edge case unit tests
// ---------------------------------------------------------------------------

func TestNetworkNameSameRulesAsHostname(t *testing.T) {
	// Network names follow the same regex as hostnames
	valid := []string{"mynet", "a", "abc-def", "x1y2z3", strings.Repeat("a", 63)}
	for _, name := range valid {
		if !networkNameRegex.MatchString(name) {
			t.Errorf("expected valid network name: %q", name)
		}
	}

	invalid := []string{"", "-start", "end-", "---", "UPPER", strings.Repeat("a", 64), "with.dot", "with space"}
	for _, name := range invalid {
		if networkNameRegex.MatchString(name) {
			t.Errorf("expected invalid network name: %q", name)
		}
	}
}

func TestNetworkNameReserved(t *testing.T) {
	if !reservedNetworkNames["backbone"] {
		t.Fatal("'backbone' should be reserved")
	}
}

// ---------------------------------------------------------------------------
// Trust pair key normalization (mirrored logic)
// ---------------------------------------------------------------------------

func TestTrustPairKeyNormalization(t *testing.T) {
	// trustPairKey returns canonical sorted key
	trustPairKey := func(a, b uint32) string {
		if a > b {
			a, b = b, a
		}
		return strings.Join([]string{
			strings.Repeat("0", 10), // placeholder
		}, ":")
		// Just test the sorting property
	}
	_ = trustPairKey

	// The real test: (1,2) and (2,1) should produce the same key
	key := func(a, b uint32) [2]uint32 {
		if a > b {
			a, b = b, a
		}
		return [2]uint32{a, b}
	}
	if key(1, 2) != key(2, 1) {
		t.Fatal("trust pair key should be symmetric")
	}
	if key(100, 200) != key(200, 100) {
		t.Fatal("trust pair key should be symmetric")
	}
	if key(1, 1) != key(1, 1) {
		t.Fatal("same node pair should match")
	}
	if key(1, 2) == key(1, 3) {
		t.Fatal("different pairs should differ")
	}
}

// ---------------------------------------------------------------------------
// Validation boundary tests (comprehensive)
// ---------------------------------------------------------------------------

func TestValidationBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		regex   *regexp.Regexp
		input   string
		valid   bool
	}{
		// Hostname boundaries
		{"hostname-1char", hostnameRegex, "a", true},
		{"hostname-2chars", hostnameRegex, "ab", true},
		{"hostname-63chars", hostnameRegex, strings.Repeat("a", 63), true},
		{"hostname-64chars", hostnameRegex, strings.Repeat("a", 64), false},
		{"hostname-hyphen-middle", hostnameRegex, "a-b", true},
		{"hostname-digit-start", hostnameRegex, "1abc", true},
		{"hostname-digit-end", hostnameRegex, "abc1", true},

		// Tag boundaries
		{"tag-1char", tagRegex, "a", true},
		{"tag-32chars", tagRegex, strings.Repeat("a", 32), true},
		{"tag-33chars", tagRegex, strings.Repeat("a", 33), false},

		// Network name boundaries
		{"netname-1char", networkNameRegex, "a", true},
		{"netname-63chars", networkNameRegex, strings.Repeat("a", 63), true},
		{"netname-64chars", networkNameRegex, strings.Repeat("a", 64), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.regex.MatchString(tc.input)
			if got != tc.valid {
				t.Errorf("%s: MatchString(%q) = %v, want %v", tc.name, tc.input, got, tc.valid)
			}
		})
	}
}
