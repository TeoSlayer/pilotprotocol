// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nodesapi is the Go client for the pilot-geo-exporter `/nodes`
// service. The service exposes the registry's online-external-node set as
// JSON, gated by a shared token, reachable via the IAP tunnel to the
// rendezvous host.
//
// Use this package from Go services that need to enumerate or filter live
// nodes — e.g. broadcast targets, onboarding agent's catalog, persona-agent
// peer discovery, validation harnesses.
//
// Wire shape (HTTP/JSON, stable v1):
//
//	GET /nodes              → full external-online node list (token required)
//	GET /nodes/by_ip?ip=…   → filtered to one IP (token required)
//	GET /metrics            → Prometheus scrape (no token)
//	GET /healthz            → liveness probe (no token)
//
// Token auth: pass via ?token=… query param OR X-Token header. This client
// uses the header by default to keep the token out of access logs.
//
// "External" = NOT in the exporter's INFRA_IPS env var. "Online" = last_seen
// within ONLINE_THRESHOLD seconds (default 600). The full list may be capped
// at NODE_INFO_MAX entries server-side; check Response.MetricTruncated.
package nodesapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the loopback address used when this client runs ON the
// rendezvous host (no IAP tunnel needed). Off-host callers should pass the
// IAP-tunneled local-port URL — typically `http://127.0.0.1:<local>` after
// `gcloud compute start-iap-tunnel pilot-rendezvous-new 9117`.
const DefaultBaseURL = "http://127.0.0.1:9117"

// DefaultTimeout matches a comfortable upper bound on `/nodes` response time
// at typical fleet sizes (~100k nodes ≈ 30 MB JSON over IAP).
const DefaultTimeout = 30 * time.Second

// Node is one entry in Response.Nodes. Field tags match the wire JSON.
type Node struct {
	NodeID       uint32  `json:"node_id"`
	IP           string  `json:"ip"`
	Country      string  `json:"country"` // ISO-3166-1 alpha-2; "XX" = unresolved
	Hostname     string  `json:"hostname"`
	Public       bool    `json:"public"`
	RealAddr     string  `json:"real_addr"`
	LastSeen     string  `json:"last_seen"`      // RFC3339, may be empty
	LastSeenUnix float64 `json:"last_seen_unix"` // 0 if missing
	AgeS         *int    `json:"age_s"`          // nil if last_seen missing
}

// Response is the envelope returned by /nodes and /nodes/by_ip.
type Response struct {
	UpdatedAt              float64  `json:"updated_at"`
	OnlineThresholdSeconds int      `json:"online_threshold_seconds"`
	InfraIPsExcluded       []string `json:"infra_ips_excluded"`
	MetricCap              int      `json:"metric_cap"`
	MetricTruncated        bool     `json:"metric_truncated"`
	RequireHostnameFilter  bool     `json:"require_hostname_filter"`
	Count                  int      `json:"count"`
	Nodes                  []Node   `json:"nodes"`
}

// Client is the minimal HTTP client. Construct with New and reuse — it's
// safe for concurrent use.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New constructs a Client. Pass an empty baseURL to use DefaultBaseURL.
// The token is required if the service is configured with NODES_TOKEN.
func New(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: DefaultTimeout},
	}
}

// WithHTTP swaps in a custom http.Client (e.g. one with a longer timeout).
// Returns the Client for chaining.
func (c *Client) WithHTTP(h *http.Client) *Client {
	c.http = h
	return c
}

// Healthz pings the no-auth liveness endpoint. Returns nil on 200.
func (c *Client) Healthz(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("healthz: HTTP %d", resp.StatusCode)
	}
	return nil
}

// List fetches the full external-online node list.
func (c *Client) List(ctx context.Context) (*Response, error) {
	return c.do(ctx, "/nodes", nil)
}

// ByIP fetches the subset of external-online nodes registered against the
// given IP. Server-side filter — much smaller payload than List + client-side.
func (c *Client) ByIP(ctx context.Context, ip string) (*Response, error) {
	if ip == "" {
		return nil, fmt.Errorf("ByIP: ip is required")
	}
	return c.do(ctx, "/nodes/by_ip", url.Values{"ip": {ip}})
}

func (c *Client) do(ctx context.Context, path string, q url.Values) (*Response, error) {
	u := c.baseURL + path
	if q != nil && len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("X-Token", c.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("unauthorized: NODES_TOKEN required (set token via env or constructor)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, u)
	}
	var out Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	return &out, nil
}

// IDs returns just the node IDs from a Response, sorted ascending.
// Convenience for callers that only care about the ID set.
func (r *Response) IDs() []uint32 {
	if r == nil {
		return nil
	}
	out := make([]uint32, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		out = append(out, n.NodeID)
	}
	return out
}

// FilterCountry returns nodes whose Country matches the given ISO code.
// Case-insensitive.
func (r *Response) FilterCountry(iso string) []Node {
	if r == nil {
		return nil
	}
	iso = strings.ToUpper(iso)
	out := make([]Node, 0, 16)
	for _, n := range r.Nodes {
		if strings.ToUpper(n.Country) == iso {
			out = append(out, n)
		}
	}
	return out
}

// FilterHostnamed returns only nodes that have a non-empty hostname (i.e.
// explicitly configured agents, not bare daemons).
func (r *Response) FilterHostnamed() []Node {
	if r == nil {
		return nil
	}
	out := make([]Node, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		if n.Hostname != "" {
			out = append(out, n)
		}
	}
	return out
}

// FilterPublic returns only nodes whose Public flag is true.
func (r *Response) FilterPublic() []Node {
	if r == nil {
		return nil
	}
	out := make([]Node, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		if n.Public {
			out = append(out, n)
		}
	}
	return out
}

// String returns a compact human-readable summary of one Node, useful for
// log lines and simple dumps.
func (n Node) String() string {
	host := n.Hostname
	if host == "" {
		host = "-"
	}
	age := "?"
	if n.AgeS != nil {
		age = strconv.Itoa(*n.AgeS) + "s"
	}
	pub := ""
	if n.Public {
		pub = " public"
	}
	return fmt.Sprintf("node_id=%-8d %-22s %s host=%s last_seen=%s ago%s",
		n.NodeID, n.IP, n.Country, host, age, pub)
}
