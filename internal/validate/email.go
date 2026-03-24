package validate

import (
	"fmt"
	"strings"
)

// Email validates an email address with basic checks:
// non-empty, contains exactly one @, domain has a dot, no spaces.
// This is not a full RFC 5322 parser — just enough to catch typos.
func Email(email string) error {
	if email == "" {
		return fmt.Errorf("email address is required")
	}
	if strings.Contains(email, " ") {
		return fmt.Errorf("email address must not contain spaces")
	}
	at := strings.Index(email, "@")
	if at < 1 {
		return fmt.Errorf("email address must contain @")
	}
	if strings.Count(email, "@") > 1 {
		return fmt.Errorf("email address must contain exactly one @")
	}
	domain := email[at+1:]
	if domain == "" {
		return fmt.Errorf("email address must have a domain after @")
	}
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("email domain must contain a dot")
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("email domain must not start or end with a dot")
	}
	return nil
}
