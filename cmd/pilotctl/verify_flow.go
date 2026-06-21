// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/protocol"
)

// verifierRequest / verifierResponse mirror pilot-verify's wire protocol:
// length-prefixed JSON frames exchanged over a Pilot stream on PortVerify.
// The verifier serves exactly one request/response per connection.
type verifierRequest struct {
	Op       string `json:"op"`                 // "begin" | "poll"
	Provider string `json:"provider,omitempty"` // begin: "github" | "google"
	NodeID   uint32 `json:"node_id,omitempty"`  // begin: address to bind the badge to
	FlowID   string `json:"flow_id,omitempty"`  // poll: handle from begin
}

type verifierResponse struct {
	OK              bool   `json:"ok"`
	Error           string `json:"error,omitempty"`
	FlowID          string `json:"flow_id,omitempty"`
	UserCode        string `json:"user_code,omitempty"`
	VerificationURI string `json:"verification_uri,omitempty"`
	Status          string `json:"status,omitempty"` // poll: "pending" | "ready" | "error"
	Badge           string `json:"badge,omitempty"`
	BadgeSig        string `json:"badge_sig,omitempty"`
}

const verifierMaxFrame = 64 << 10

func writeVerifierFrame(w io.Writer, v interface{}) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(payload) > verifierMaxFrame {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

func readVerifierFrame(r io.Reader, v interface{}) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > verifierMaxFrame {
		return fmt.Errorf("frame too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

// verifierRoundtrip dials the verifier on PortVerify, sends one request,
// reads one response, and closes — the verifier serves one op per conn.
func verifierRoundtrip(d *driver.Driver, vaddr string, req verifierRequest) (verifierResponse, error) {
	conn, err := d.Dial(vaddr + ":" + strconv.Itoa(int(protocol.PortVerify)))
	if err != nil {
		return verifierResponse{}, fmt.Errorf("dial verifier %s: %w", vaddr, err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	return verifierExchange(conn, req)
}

// verifierExchange writes one request frame and reads one response frame on an
// already-open stream (separated from dialing so it is unit-testable).
func verifierExchange(conn io.ReadWriter, req verifierRequest) (verifierResponse, error) {
	if err := writeVerifierFrame(conn, req); err != nil {
		return verifierResponse{}, err
	}
	var resp verifierResponse
	if err := readVerifierFrame(conn, &resp); err != nil {
		return verifierResponse{}, err
	}
	if !resp.OK {
		return resp, fmt.Errorf("verifier: %s", resp.Error)
	}
	return resp, nil
}

// resolveVerifierAddr accepts either a literal Pilot address or a hostname to
// resolve (default "verify").
func resolveVerifierAddr(d *driver.Driver, ref string) string {
	if _, err := protocol.ParseAddr(ref); err == nil {
		return ref
	}
	res, err := d.ResolveHostname(ref)
	if err != nil {
		fatalHint("not_found",
			"pass --verifier <address|hostname>, or check the verifier service is registered",
			"cannot resolve verifier %q: %v", ref, err)
	}
	addr, _ := res["address"].(string)
	if addr == "" {
		fatalCode("not_found", "verifier %q resolved with no address", ref)
	}
	return addr
}

// cmdVerifyProvider runs the self-service device-flow end to end: dial the
// verifier, start a verification bound to our own address, show the user the
// device code, poll until they authorize in their browser, then submit the
// minted badge to the registry through the daemon (proving key ownership).
//
//	pilotctl verify --provider github [--verifier <address|hostname>]
func cmdVerifyProvider(flags map[string]string, provider string) {
	verifierRef := flagString(flags, "verifier", "verify")

	d := connectDriver()
	defer d.Close()
	info, err := d.Info()
	if err != nil {
		fatalCode("connection_failed", "verify: cannot reach the daemon (is it running?): %v", err)
	}
	nodeF, _ := info["node_id"].(float64)
	if nodeF == 0 {
		fatalCode("internal_error", "verify: daemon has no node id yet (not registered?)")
	}

	vaddr := resolveVerifierAddr(d, verifierRef)

	begin, err := verifierRoundtrip(d, vaddr, verifierRequest{Op: "begin", Provider: provider, NodeID: uint32(nodeF)})
	if err != nil {
		fatalCode("connection_failed", "verify begin: %v", err)
	}
	if begin.UserCode == "" || begin.VerificationURI == "" {
		fatalCode("internal_error", "verifier returned no device code")
	}

	// Device-code instructions go to stderr so JSON stdout stays clean.
	fmt.Fprintf(os.Stderr, "\nTo verify your address via %s:\n  1. open %s\n  2. enter code: %s\n\nWaiting for authorization (Ctrl-C to cancel)...\n",
		provider, begin.VerificationURI, begin.UserCode)

	deadline := time.Now().Add(10 * time.Minute)
	var badge, badgeSig string
	// Tolerate transient poll failures (a dropped frame, a relay blip) rather
	// than aborting a flow the user may have already half-completed. Only give
	// up after several consecutive errors.
	const maxPollErrors = 5
	pollErrors := 0
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		poll, err := verifierRoundtrip(d, vaddr, verifierRequest{Op: "poll", FlowID: begin.FlowID})
		if err != nil {
			pollErrors++
			if pollErrors >= maxPollErrors {
				fatalCode("connection_failed", "verify poll: %d consecutive failures: %v", pollErrors, err)
			}
			continue
		}
		pollErrors = 0
		switch poll.Status {
		case "ready":
			badge, badgeSig = poll.Badge, poll.BadgeSig
		case "error":
			fatalCode("permission_denied", "verification failed: %s", poll.Error)
		}
		if badge != "" {
			break
		}
	}
	if badge == "" {
		fatalCode("deadline_exceeded", "verification timed out; no authorization received")
	}

	resp, err := d.SubmitBadge(badge, badgeSig)
	if err != nil {
		fatalCode("connection_failed", "submit badge: %v", err)
	}
	fmt.Fprintf(os.Stderr, "\n✓ Verified via %s — badge submitted.\n", provider)
	output(resp)
}
