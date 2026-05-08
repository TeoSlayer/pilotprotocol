// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// archiveToInstall maps binary names in the release archive to the filenames
// used by install.sh in the install directory. The archive uses short names;
// install.sh adds the "pilot-" prefix to avoid conflicts with system binaries.
var archiveToInstall = map[string]string{
	"daemon":   "pilot-daemon",
	"gateway":  "pilot-gateway",
	"updater":  "pilot-updater",
	"pilotctl": "pilotctl",
}

// maxDownloadBytes caps the size of any single downloaded file.
const maxDownloadBytes = 256 * 1024 * 1024

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
	exitFn func(int) // injectable for testing; defaults to os.Exit
}

// GitHubRelease represents a subset of the GitHub release API response.
type GitHubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []GitHubAsset `json:"assets"`
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
		exitFn: os.Exit,
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

	// On startup, catch any missed daemon restart from a previous update cycle
	// (e.g. old macOS updater replaced the binary but never called launchctl).
	u.recoverPendingRestart()

	// Run once immediately on start.
	u.checkOnce()

	ticker := time.NewTicker(u.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Add 0-30s jitter to avoid thundering herd.
			// Use NewTimer + Stop so the goroutine is reclaimed immediately
			// on stopCh rather than lingering until the jitter duration
			// expires (time.After leak on early exit).
			jitter := time.Duration(rand.Int63n(int64(30 * time.Second)))
			jitterTimer := time.NewTimer(jitter)
			select {
			case <-jitterTimer.C:
			case <-u.stopCh:
				jitterTimer.Stop()
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
	u.touchRestartRecord()
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
	daemonPath := filepath.Join(u.config.InstallDir, "pilot-daemon")
	if _, err := os.Stat(daemonPath); err != nil {
		return Semver{}, fmt.Errorf("daemon binary not found at %s: %w", daemonPath, err)
	}

	// Read the version file we write after each update.
	versionFile := filepath.Join(u.config.InstallDir, ".pilot-version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		// No version file means this is a pre-updater install. Treat as 0.0.0
		// so any published release triggers an update immediately.
		slog.Warn("no version file, treating current version as 0.0.0", "path", versionFile)
		return Semver{}, nil
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

	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return fmt.Errorf("read staging dir: %w", err)
	}

	updaterReplaced := false
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		installName, ok := archiveToInstall[entry.Name()]
		if !ok {
			slog.Debug("skipping server binary", "name", entry.Name())
			continue
		}
		src := filepath.Join(stagingDir, entry.Name())
		dst := filepath.Join(u.config.InstallDir, installName)
		if err := replaceBinary(src, dst); err != nil {
			return fmt.Errorf("replace %s: %w", installName, err)
		}
		slog.Info("replaced binary", "name", installName)
		if installName == "pilot-updater" {
			updaterReplaced = true
		}
	}

	// Write version file before any exit path so the new process doesn't
	// re-download the same release when it starts. Fsync ensures the write
	// survives an immediate os.Exit(0).
	if err := writeFileSync(
		filepath.Join(u.config.InstallDir, ".pilot-version"),
		[]byte(release.TagName+"\n"),
		0644,
	); err != nil {
		slog.Warn("failed to write version file", "error", err)
	}

	// If the updater binary itself was replaced, exit so launchd/systemd
	// restarts the process with the new binary. On startup the new process
	// runs recoverPendingRestart() which will handle the daemon restart.
	// Explicitly clean up tmpDir first since defer won't run after os.Exit.
	if updaterReplaced {
		os.RemoveAll(tmpDir)
		slog.Info("updater binary replaced — exiting for process manager to restart with new binary")
		u.exitFn(0)
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

	_, err = io.Copy(f, io.LimitReader(resp.Body, maxDownloadBytes))
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
	// Write to a temp file beside the destination, then atomically rename.
	// This avoids "text file busy" on Linux (rename unlinks the old inode
	// while the running process keeps its file descriptor open) and prevents
	// a partial write leaving a corrupt binary at the destination path.
	tmp := dst + ".new"
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	tmpFile, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(tmpFile, srcFile); err != nil {
		tmpFile.Close()
		os.Remove(tmp)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// Atomic swap — on the same filesystem this is a single syscall.
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (u *Updater) recoverPendingRestart() {
	// Only attempt recovery if the updater has previously completed at least
	// one update cycle. On a fresh install there is no history to recover.
	versionFile := filepath.Join(u.config.InstallDir, ".pilot-version")
	if _, err := os.Stat(versionFile); err != nil {
		return
	}

	daemonBin := filepath.Join(u.config.InstallDir, "pilot-daemon")
	restartRecord := filepath.Join(u.config.InstallDir, ".daemon-last-restart")

	binStat, err := os.Stat(daemonBin)
	if err != nil {
		return
	}
	recordStat, err := os.Stat(restartRecord)
	if err != nil || binStat.ModTime().After(recordStat.ModTime()) {
		slog.Info("daemon binary updated since last restart, triggering restart")
		u.signalDaemonRestart()
		u.touchRestartRecord()
	}
}

func (u *Updater) touchRestartRecord() {
	path := filepath.Join(u.config.InstallDir, ".daemon-last-restart")
	if err := writeFileSync(path, []byte(time.Now().Format(time.RFC3339)+"\n"), 0644); err != nil {
		slog.Warn("failed to update restart record", "error", err)
	}
}

// writeFileSync writes data to path and fsyncs before returning so the write
// survives an immediately following os.Exit(0).
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (u *Updater) signalDaemonRestart() {
	if runtime.GOOS == "darwin" {
		u.signalDaemonRestartDarwin()
		return
	}
	u.signalDaemonRestartLinux()
}

func (u *Updater) signalDaemonRestartDarwin() {
	// On macOS the daemon is managed by launchd. Use launchctl kickstart -k
	// to kill the running instance and restart it immediately. The label
	// matches the plist written by install.sh.
	uid := os.Getuid()
	label := "network.pilotprotocol.pilot-daemon"
	target := fmt.Sprintf("gui/%d/%s", uid, label)
	out, err := exec.Command("launchctl", "kickstart", "-k", target).CombinedOutput()
	if err != nil {
		slog.Warn("launchctl kickstart failed — restart daemon manually",
			"target", target, "err", err, "output", strings.TrimSpace(string(out)))
		return
	}
	slog.Info("daemon restarted via launchctl", "target", target)
}

func (u *Updater) signalDaemonRestartLinux() {
	// On Linux, find the daemon process via /proc/<pid>/exe and send SIGTERM.
	// systemd Restart=on-failure will relaunch it automatically.
	daemonPath := filepath.Join(u.config.InstallDir, "pilot-daemon")
	entries, err := os.ReadDir("/proc")
	if err != nil {
		slog.Warn("cannot read /proc — restart daemon manually")
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
	slog.Warn("daemon process not found — restart daemon manually")
}
