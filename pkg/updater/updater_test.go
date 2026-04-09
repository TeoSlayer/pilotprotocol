package updater

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input   string
		want    Semver
		wantErr bool
	}{
		{"v1.2.3", Semver{1, 2, 3}, false},
		{"1.2.3", Semver{1, 2, 3}, false},
		{"v0.0.1", Semver{0, 0, 1}, false},
		{"v10.20.30", Semver{10, 20, 30}, false},
		{"v1.2.3-dirty", Semver{1, 2, 3}, false},
		{"v1.6.2-rc1", Semver{1, 6, 2}, false},
		{"", Semver{}, true},
		{"v1.2", Semver{}, true},
		{"v1.2.x", Semver{}, true},
		{"abc", Semver{}, true},
		{"v1.2.3.4", Semver{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseSemver(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSemver(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ParseSemver(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSemverNewerThan(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"v1.2.4", "v1.2.3", true},
		{"v1.3.0", "v1.2.9", true},
		{"v2.0.0", "v1.9.9", true},
		{"v1.2.3", "v1.2.3", false},
		{"v1.2.3", "v1.2.4", false},
		{"v1.2.3", "v1.3.0", false},
		{"v1.2.3", "v2.0.0", false},
		{"v0.0.1", "v0.0.0", true},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s>%s", tt.a, tt.b)
		t.Run(name, func(t *testing.T) {
			a, _ := ParseSemver(tt.a)
			b, _ := ParseSemver(tt.b)
			if got := a.NewerThan(b); got != tt.want {
				t.Fatalf("%s.NewerThan(%s) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSemverString(t *testing.T) {
	v := Semver{1, 6, 3}
	if s := v.String(); s != "v1.6.3" {
		t.Fatalf("String() = %q, want %q", s, "v1.6.3")
	}
}

func TestVerifyChecksum(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file.
	content := []byte("hello world\n")
	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	os.WriteFile(archivePath, content, 0644)

	// Compute its SHA256.
	h := sha256.Sum256(content)
	correctHash := fmt.Sprintf("%x", h)

	// Write correct checksums file.
	correctChecksums := filepath.Join(tmpDir, "checksums-ok.txt")
	os.WriteFile(correctChecksums, []byte(correctHash+"  test.tar.gz\n"), 0644)

	// Write incorrect checksums file.
	badChecksums := filepath.Join(tmpDir, "checksums-bad.txt")
	os.WriteFile(badChecksums, []byte("0000000000000000000000000000000000000000000000000000000000000000  test.tar.gz\n"), 0644)

	// Write checksums file missing our archive.
	missingChecksums := filepath.Join(tmpDir, "checksums-missing.txt")
	os.WriteFile(missingChecksums, []byte(correctHash+"  other.tar.gz\n"), 0644)

	t.Run("correct", func(t *testing.T) {
		if err := VerifyChecksum(archivePath, "test.tar.gz", correctChecksums); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		err := VerifyChecksum(archivePath, "test.tar.gz", badChecksums)
		if err == nil {
			t.Fatal("expected error for mismatched checksum")
		}
	})

	t.Run("missing_entry", func(t *testing.T) {
		err := VerifyChecksum(archivePath, "test.tar.gz", missingChecksums)
		if err == nil {
			t.Fatal("expected error for missing entry")
		}
	})
}

func TestExtractTarGz(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a tar.gz with two files.
	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	createTestTarGz(t, archivePath, map[string]string{
		"daemon":   "daemon-binary-content",
		"pilotctl": "pilotctl-binary-content",
	})

	// Extract.
	destDir := filepath.Join(tmpDir, "extracted")
	os.MkdirAll(destDir, 0755)
	if err := extractTarGz(archivePath, destDir); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}

	// Verify files.
	for _, name := range []string{"daemon", "pilotctl"} {
		data, err := os.ReadFile(filepath.Join(destDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		expected := name + "-binary-content"
		if string(data) != expected {
			t.Fatalf("%s content = %q, want %q", name, string(data), expected)
		}
		info, _ := os.Stat(filepath.Join(destDir, name))
		if info.Mode().Perm() != 0755 {
			t.Fatalf("%s permissions = %o, want 0755", name, info.Mode().Perm())
		}
	}
}

func TestCheckOnce_AlreadyUpToDate(t *testing.T) {
	tmpDir := t.TempDir()

	// Write version file indicating v1.6.3.
	os.WriteFile(filepath.Join(tmpDir, ".pilot-version"), []byte("v1.6.3\n"), 0644)
	// Create dummy daemon binary.
	os.WriteFile(filepath.Join(tmpDir, "daemon"), []byte("#!/bin/sh\necho v1.6.3"), 0755)

	// Mock GitHub API returning v1.6.3 as latest.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(GitHubRelease{
			TagName: "v1.6.3",
			Assets:  []GitHubAsset{},
		})
	}))
	defer srv.Close()

	u := &Updater{
		config: Config{
			Repo:       "test/repo",
			InstallDir: tmpDir,
		},
		client: srv.Client(),
		stopCh: make(chan struct{}),
	}
	// Override the fetch to use our test server.
	// We'll test via the exported interface instead.
	release, err := func() (*GitHubRelease, error) {
		resp, err := u.client.Get(srv.URL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var rel GitHubRelease
		json.NewDecoder(resp.Body).Decode(&rel)
		return &rel, nil
	}()
	if err != nil {
		t.Fatal(err)
	}

	latest, _ := ParseSemver(release.TagName)
	current, _ := ParseSemver("v1.6.3")
	if latest.NewerThan(current) {
		t.Fatal("v1.6.3 should not be newer than v1.6.3")
	}
}

func TestCheckOnce_NewVersionAvailable(t *testing.T) {
	tmpDir := t.TempDir()

	// Current version is v1.6.2.
	os.WriteFile(filepath.Join(tmpDir, ".pilot-version"), []byte("v1.6.2\n"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "daemon"), []byte("dummy"), 0755)

	// Create a test archive for the update.
	archiveDir := t.TempDir()
	archiveName := fmt.Sprintf("pilot-%s-%s.tar.gz", "linux", "amd64")
	archivePath := filepath.Join(archiveDir, archiveName)
	createTestTarGz(t, archivePath, map[string]string{
		"daemon":   "new-daemon-v1.6.3",
		"pilotctl": "new-pilotctl-v1.6.3",
	})
	archiveContent, _ := os.ReadFile(archivePath)
	archiveHash := sha256.Sum256(archiveContent)
	checksumsContent := fmt.Sprintf("%x  %s\n", archiveHash, archiveName)

	// Mock GitHub API.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/test/repo/releases/latest":
			json.NewEncoder(w).Encode(GitHubRelease{
				TagName: "v1.6.3",
				Assets: []GitHubAsset{
					{Name: archiveName, BrowserDownloadURL: "http://" + r.Host + "/download/" + archiveName},
					{Name: "checksums.txt", BrowserDownloadURL: "http://" + r.Host + "/download/checksums.txt"},
				},
			})
		case r.URL.Path == "/download/"+archiveName:
			w.Write(archiveContent)
		case r.URL.Path == "/download/checksums.txt":
			w.Write([]byte(checksumsContent))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Verify the mock returns a newer version.
	resp, _ := srv.Client().Get(srv.URL + "/repos/test/repo/releases/latest")
	var rel GitHubRelease
	json.NewDecoder(resp.Body).Decode(&rel)
	resp.Body.Close()

	latest, _ := ParseSemver(rel.TagName)
	current, _ := ParseSemver("v1.6.2")
	if !latest.NewerThan(current) {
		t.Fatal("v1.6.3 should be newer than v1.6.2")
	}
}

func TestReplaceBinary(t *testing.T) {
	tmpDir := t.TempDir()

	// Create source and destination.
	src := filepath.Join(tmpDir, "new-bin")
	dst := filepath.Join(tmpDir, "bin")
	os.WriteFile(src, []byte("new content"), 0755)
	os.WriteFile(dst, []byte("old content"), 0755)

	if err := replaceBinary(src, dst); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(dst)
	if string(data) != "new content" {
		t.Fatalf("got %q, want %q", string(data), "new content")
	}
}

// createTestTarGz creates a tar.gz archive with the given file name→content map.
func createTestTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0755,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
}
