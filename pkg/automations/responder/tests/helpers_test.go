package responder_test

import (
	"os"
	"testing"
)

// writeTempFile writes content to a temp file scoped to the test and returns its path.
func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "endpoints-*.yaml")
	if err != nil {
		t.Fatalf("writeTempFile: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writeTempFile write: %v", err)
	}
	return f.Name()
}
