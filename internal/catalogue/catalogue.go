// Package catalogue loads the release-signed app-store catalogue and exposes
// the per-app publisher "pins" the daemon uses as its trust anchor.
//
// The catalogue (signed by the embedded catalogue key, see internal/catalogtrust)
// is the root of trust: it declares, per app id, the ed25519 publisher key that
// app's manifest must be signed by. The app-store supervisor confirms each
// non-sideloaded app's manifest.Store.Publisher matches this pin before spawning
// (manifest.VerifyTrustAnchor). This package is what feeds those pins to the
// supervisor via appstore.Config.CataloguePublisher.
package catalogue

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/pilotprotocol/internal/catalogtrust"
)

// DefaultURL is the production catalogue location; override with
// $PILOT_APPSTORE_CATALOG_URL (kept identical to pilotctl's default).
const DefaultURL = "https://raw.githubusercontent.com/pilot-protocol/pilotprotocol/main/catalogue/catalogue.json"

// URL returns the catalogue URL the daemon should load — env override wins.
func URL() string {
	if u := strings.TrimSpace(os.Getenv("PILOT_APPSTORE_CATALOG_URL")); u != "" {
		return u
	}
	return DefaultURL
}

// entry is the minimal slice of a catalogue entry this package needs: the app
// id and the publisher pin. All other catalogue fields are ignored.
type entry struct {
	ID        string `json:"id"`
	Publisher string `json:"publisher"`
}

type doc struct {
	Version int     `json:"version"`
	Apps    []entry `json:"apps"`
}

// LoadPublishers fetches the catalogue at url (and its detached <url>.sig),
// verifies the signature against the embedded catalogue key (fail-closed), and
// returns appID -> publisher pin ("ed25519:<base64>") for every entry that
// declares a publisher. The signature check is the same gate pilotctl uses at
// install time — a substituted catalogue cannot change the pins.
func LoadPublishers(url string) (map[string]string, error) {
	data, err := fetch(url)
	if err != nil {
		return nil, fmt.Errorf("fetch catalogue from %s: %w", url, err)
	}
	sigRaw, err := fetch(url + ".sig")
	if err != nil {
		return nil, fmt.Errorf("fetch catalogue signature %s.sig: %w", url, err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return nil, fmt.Errorf("decode catalogue signature: %w", err)
	}
	if err := catalogtrust.Verify(data, sig); err != nil {
		return nil, fmt.Errorf("catalogue signature: %w", err)
	}
	var d doc
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse catalogue: %w", err)
	}
	pins := make(map[string]string, len(d.Apps))
	for _, e := range d.Apps {
		if e.ID != "" && strings.TrimSpace(e.Publisher) != "" {
			pins[e.ID] = e.Publisher
		}
	}
	return pins, nil
}

// fetch reads up to 1 MiB from a file://, https://, or http://localhost URL.
// Mirrors pilotctl's openURL: plaintext http is refused for non-loopback hosts.
func fetch(raw string) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	var body io.ReadCloser
	switch u.Scheme {
	case "file":
		f, err := os.Open(u.Path)
		if err != nil {
			return nil, err
		}
		body = f
	case "https":
		body, err = httpGet(raw)
		if err != nil {
			return nil, err
		}
	case "http":
		if h := u.Hostname(); h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return nil, fmt.Errorf("refusing plaintext http for non-localhost host %q (use https)", h)
		}
		body, err = httpGet(raw)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported url scheme %q", u.Scheme)
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return data, nil
}

func httpGet(raw string) (io.ReadCloser, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(raw) //nolint:noctx // short-lived, bounded by client.Timeout
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close() // discarding on the error path; the status error below is what matters
		return nil, fmt.Errorf("GET %s: status %d", raw, resp.StatusCode)
	}
	return resp.Body, nil
}

// Provider serves catalogue publisher pins to the app-store supervisor and
// refreshes them from the signed catalogue. Safe for concurrent use: the
// supervisor reads via Publisher on every scan while a background loop writes
// via Refresh. A disk cache lets the daemon survive a transient catalogue
// outage on restart (fail-closed only when there is neither a live catalogue
// nor a cache).
type Provider struct {
	url       string
	cachePath string

	mu   sync.RWMutex
	pins map[string]string

	// refresh-on-miss: an installed app with no pin is likely one that was
	// pinned in the catalogue after our last periodic refresh. Rather than make
	// it wait for the 10-minute tick (and be refused meanwhile), a pin miss
	// triggers a rate-limited background refresh so the next supervisor scan
	// can spawn it.
	refreshMu       sync.Mutex
	lastRefresh     time.Time
	refreshInFlight bool
	minRefreshGap   time.Duration
}

// missRefreshGap bounds how often a pin miss may trigger a catalogue refetch, so
// a genuinely unpinned app can't cause a refresh storm.
const missRefreshGap = 30 * time.Second

// NewProvider builds a Provider for the catalogue at url, caching the last
// verified pin set at cachePath (empty disables the cache).
func NewProvider(url, cachePath string) *Provider {
	return &Provider{url: url, cachePath: cachePath, pins: map[string]string{}, minRefreshGap: missRefreshGap}
}

// Publisher implements appstore.Config.CataloguePublisher: it returns the
// catalogue-pinned publisher for appID and whether appID is pinned. On a miss it
// kicks off a rate-limited background refresh (see refreshOnMiss), so an app
// that was pinned since the last periodic refresh becomes spawnable within a
// scan cycle instead of after the next 10-minute tick.
func (p *Provider) Publisher(appID string) (string, bool) {
	p.mu.RLock()
	pub, ok := p.pins[appID]
	p.mu.RUnlock()
	if !ok {
		p.refreshOnMiss()
	}
	return pub, ok
}

// refreshOnMiss launches a single background Refresh if one isn't already
// running and the last refresh is older than minRefreshGap. Non-blocking: the
// caller (a supervisor scan) never waits on the network.
func (p *Provider) refreshOnMiss() {
	p.refreshMu.Lock()
	if p.refreshInFlight || time.Since(p.lastRefresh) < p.minRefreshGap {
		p.refreshMu.Unlock()
		return
	}
	p.refreshInFlight = true
	p.refreshMu.Unlock()
	go func() {
		_ = p.Refresh()
		p.refreshMu.Lock()
		p.refreshInFlight = false
		p.refreshMu.Unlock()
	}()
}

// Refresh fetches + verifies the catalogue and atomically swaps in the new pin
// set. On success it also writes the disk cache. On failure the previous pins
// are kept (so a transient outage doesn't suddenly fail-close running apps).
func (p *Provider) Refresh() error {
	p.refreshMu.Lock()
	p.lastRefresh = time.Now()
	p.refreshMu.Unlock()
	pins, err := LoadPublishers(p.url)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.pins = pins
	p.mu.Unlock()
	p.writeCache(pins)
	return nil
}

// LoadCache populates the pin set from the disk cache. Best-effort: used at
// startup when the initial Refresh fails (e.g. the daemon booted offline).
// Returns true if any pins were loaded.
func (p *Provider) LoadCache() bool {
	if p.cachePath == "" {
		return false
	}
	data, err := os.ReadFile(p.cachePath)
	if err != nil {
		return false
	}
	var pins map[string]string
	if err := json.Unmarshal(data, &pins); err != nil || len(pins) == 0 {
		return false
	}
	p.mu.Lock()
	p.pins = pins
	p.mu.Unlock()
	return true
}

func (p *Provider) writeCache(pins map[string]string) {
	if p.cachePath == "" {
		return
	}
	data, err := json.Marshal(pins)
	if err != nil {
		return
	}
	tmp := p.cachePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, p.cachePath) // atomic replace; best-effort
}

// Count returns how many apps are currently pinned (for startup logging).
func (p *Provider) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.pins)
}
