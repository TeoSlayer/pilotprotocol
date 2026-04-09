package updater

import (
	"fmt"
	"strconv"
	"strings"
)

// Semver represents a parsed semantic version.
type Semver struct {
	Major int
	Minor int
	Patch int
}

// ParseSemver parses a version string like "v1.2.3" or "1.2.3" or "v1.2.3-dirty".
// It strips the "v" prefix and any suffix after a hyphen.
func ParseSemver(s string) (Semver, error) {
	s = strings.TrimPrefix(s, "v")
	// Strip anything after hyphen (e.g. "-dirty", "-rc1")
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		s = s[:idx]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Semver{}, fmt.Errorf("invalid semver: %q", s)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return Semver{}, fmt.Errorf("invalid major: %w", err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return Semver{}, fmt.Errorf("invalid minor: %w", err)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return Semver{}, fmt.Errorf("invalid patch: %w", err)
	}
	return Semver{Major: major, Minor: minor, Patch: patch}, nil
}

// NewerThan returns true if v is strictly newer than other.
func (v Semver) NewerThan(other Semver) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	return v.Patch > other.Patch
}

// String returns the version as "vMAJOR.MINOR.PATCH".
func (v Semver) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}
