package wiraid

import (
	"fmt"
	"strconv"
	"strings"
)

// semver parses a version string like "1.2.3" or "v1.2.3" into [major, minor, patch].
func parseSemver(v string) ([3]int, error) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, ".", 3)
	var out [3]int
	for i, p := range parts {
		if i >= 3 {
			break
		}
		// strip pre-release/build metadata
		p = strings.FieldsFunc(p, func(r rune) bool { return r == '-' || r == '+' })[0]
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, fmt.Errorf("invalid semver %q: %w", v, err)
		}
		out[i] = n
	}
	return out, nil
}

// semverGTE returns true if version a >= b.
// Empty strings are treated as "0.0.0" (always satisfied).
func semverGTE(a, b string) bool {
	if b == "" {
		return true
	}
	if a == "" {
		return false
	}
	av, err := parseSemver(a)
	if err != nil {
		return false
	}
	bv, err := parseSemver(b)
	if err != nil {
		return false
	}
	for i := range av {
		if av[i] > bv[i] {
			return true
		}
		if av[i] < bv[i] {
			return false
		}
	}
	return true // equal
}
