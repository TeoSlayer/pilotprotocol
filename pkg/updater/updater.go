package updater

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config holds the updater configuration.
type Config struct {
	CheckInterval time.Duration
	Repo          string // "owner/repo"
	InstallDir    string
	Version       string // updater's own version (used for user-agent)
}

// Updater periodically checks GitHub Releases for new versions and optionally applies them.
type Updater struct {
	config Config
	client *http.Client
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// GitHubRelease represents a subset of the GitHub release API response.
type GitHubRelease struct {
	TagName string         `json:"tag_name"`
	Assets  []GitHubAsset  `json:"assets"`
}

// GitHubAsset represents a release asset.
type GitHubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// New creates a new Updater.
func New(cfg Config) *Updater {
	return &Updater{
		config: cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		stopCh: make(chan struct{}),
	}
}

// Start begins the periodic check loop.
func (u *Updater) Start() {
	u.wg.Add(1)
	go u.checkLoop()
}

// Stop signals the check loop to stop and waits for it to finish.
func (u *Updater) Stop() {
	close(u.stopCh)
	u.wg.Wait()
}

func (u *Updater) checkLoop() {
	defer u.wg.Done()

	// Run once immediately on start.
	u.checkOnce()

	ticker := time.NewTicker(u.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Add 0-30s jitter to avoid thundering herd.
			jitter := time.Duration(rand.Int63n(int64(30 * time.Second)))
			select {
			case <-time.After(jitter):
			case <-u.stopCh:
				return
			}
			u.checkOnce()
		case <-u.stopCh:
			return
		}
	}
}

func (u *Updater) checkOnce() {
	slog.Debug("checking for updates")

	release, err := u.fetchLatestRelease()
	if err != nil {
		slog.Error("failed to fetch latest release", "error", err)
		return
	}

	latest, err := ParseSemver(release.TagName)
	if err != nil {
		slog.Error("failed to parse release tag", "tag", release.TagName, "error", err)
		return
	}

	current, err := u.currentVersion()
	if err != nil {
		slog.Error("failed to get current version", "error", err)
		return
	}

	slog.Info("version check", "current", current.String(), "latest", latest.String())

	if !latest.NewerThan(current) {
		slog.Debug("already up to date")
		return
	}

	slog.Info("new version available, updating", "current", current.String(), "latest", latest.String())

	if err := u.applyUpdate(release); err != nil {
		slog.Error("failed to apply update", "error", err)
		return
	}

	slog.Info("update applied successfully", "version", latest.String())
}

func (u *Updater) fetchLatestRelease() (*GitHubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.config.Repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if u.config.Version != "" {
		req.Header.Set("User-Agent", "pilot-updater/"+u.config.Version)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &release, nil
}

func (u *Updater) currentVersion() (Semver, error) {
	daemonPath := filepath.Join(u.config.InstallDir, "daemon")
	if _, err := os.Stat(daemonPath); err != nil {
		return Semver{}, fmt.Errorf("daemon binary not found at %s: %w", daemonPath, err)
	}

	// Read the version file we write after each update.
	versionFile := filepath.Join(u.config.InstallDir, ".pilot-version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		// No version file — this is a pre-updater install.
		// Try to run daemon -version.
		return Semver{}, fmt.Errorf("no version file at %s (run daemon -version manually to check): %w", versionFile, err)
	}
	return ParseSemver(strings.TrimSpace(string(data)))
}

func (u *Updater) applyUpdate(release *GitHubRelease) error {
	archiveName := fmt.Sprintf("pilot-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	var archiveURL, checksumsURL string

	for _, a := range release.Assets {
		switch a.Name {
		case archiveName:
			archiveURL = a.BrowserDownloadURL
		case "checksums.txt":
			checksumsURL = a.BrowserDownloadURL
		}
	}

	if archiveURL == "" {
		return fmt.Errorf("no asset %q in release %s", archiveName, release.TagName)
	}

	tmpDir, err := os.MkdirTemp("", "pilot-update-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download archive.
	archivePath := filepath.Join(tmpDir, archiveName)
	if err := u.downloadFile(archiveURL, archivePath); err != nil {
		return fmt.Errorf("download archive: %w", err)
	}

	// If checksums available, verify.
	if checksumsURL != "" {
		checksumsPath := filepath.Join(tmpDir, "checksums.txt")
		if err := u.downloadFile(checksumsURL, checksumsPath); err != nil {
			slog.Warn("failed to download checksums, skipping verification", "error", err)
		} else if err := VerifyChecksum(archivePath, archiveName, checksumsPath); err != nil {
			return fmt.Errorf("checksum verification failed: %w", err)
		}
		slog.Info("checksum verified", "archive", archiveName)
	}

	// Extract to staging directory.
	stagingDir := filepath.Join(tmpDir, "staging")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}
	if err := extractTarGz(archivePath, stagingDir); err != nil {
		return fmt.Errorf("extract archive: %w", err)
	}

	// Only replace client binaries — server binaries (registry, beacon,
	// rendezvous, nameserver) are managed separately.
	clientBins := map[string]bool{
		"daemon":   true,
		"pilotctl": true,
		"gateway":  true,
		"updater":  true,
	}

	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return fmt.Errorf("read staging dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !clientBins[entry.Name()] {
			slog.Debug("skipping server binary", "name", entry.Name())
			continue
		}
		src := filepath.Join(stagingDir, entry.Name())
		dst := filepath.Join(u.config.InstallDir, entry.Name())
		if err := replaceBinary(src, dst); err != nil {
			return fmt.Errorf("replace %s: %w", entry.Name(), err)
		}
		slog.Info("replaced binary", "name", entry.Name())
	}

	// Write version file for future comparison.
	versionFile := filepath.Join(u.config.InstallDir, ".pilot-version")
	if err := os.WriteFile(versionFile, []byte(release.TagName+"\n"), 0644); err != nil {
		slog.Warn("failed to write version file", "error", err)
	}

	// Signal daemon to restart (SIGTERM for graceful shutdown).
	u.signalDaemonRestart()

	return nil
}

func (u *Updater) downloadFile(url, dst string) error {
	resp, err := u.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

// VerifyChecksum checks the SHA256 of archivePath against the checksums file.
func VerifyChecksum(archivePath, archiveName, checksumsPath string) error {
	// Read checksums file.
	data, err := os.ReadFile(checksumsPath)
	if err != nil {
		return fmt.Errorf("read checksums: %w", err)
	}

	// Find the line for our archive.
	var expectedHash string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "hash  filename" or "hash filename"
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == archiveName {
			expectedHash = parts[0]
			break
		}
	}
	if expectedHash == "" {
		return fmt.Errorf("no checksum found for %s", archiveName)
	}

	// Compute actual hash.
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actualHash := hex.EncodeToString(h.Sum(nil))

	if actualHash != expectedHash {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	return nil
}

func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}

		// Only extract regular files, skip directories and symlinks.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Sanitize path — prevent directory traversal.
		name := filepath.Base(hdr.Name)
		if name == "." || name == ".." {
			continue
		}

		dst := filepath.Join(destDir, name)
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return fmt.Errorf("write %s: %w", name, err)
		}
		out.Close()
	}
	return nil
}

func replaceBinary(src, dst string) error {
	// Remove old binary first (handles "text file busy" on Linux).
	os.Remove(dst)

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func (u *Updater) signalDaemonRestart() {
	// Find daemon process and send SIGTERM.
	// We look for a process whose executable path matches our install dir.
	daemonPath := filepath.Join(u.config.InstallDir, "daemon")
	entries, err := os.ReadDir("/proc")
	if err != nil {
		// Not on Linux (macOS, etc.) — try finding by name.
		slog.Info("daemon restart: send SIGTERM to daemon process manually, or use systemd to auto-restart")
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			continue
		}
		if exe == daemonPath {
			pid := 0
			fmt.Sscanf(entry.Name(), "%d", &pid)
			if pid > 0 {
				slog.Info("sending SIGTERM to daemon", "pid", pid)
				syscall.Kill(pid, syscall.SIGTERM)
				return
			}
		}
	}
	slog.Warn("daemon process not found, manual restart may be needed")
}
