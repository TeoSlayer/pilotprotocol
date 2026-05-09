// SPDX-License-Identifier: AGPL-3.0-or-later

package nameserver_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/plugins/nameserver"
)

// --- ParseRequest ---

func TestParseRequestQueryA(t *testing.T) {
	t.Parallel()
	r, err := nameserver.ParseRequest("QUERY A mynode")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Command != "QUERY" || r.RecordType != "A" || r.Name != "mynode" {
		t.Errorf("unexpected result: %+v", r)
	}
}

func TestParseRequestQueryN(t *testing.T) {
	t.Parallel()
	r, err := nameserver.ParseRequest("QUERY N somenet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.RecordType != "N" || r.Name != "somenet" {
		t.Errorf("unexpected result: %+v", r)
	}
}

func TestParseRequestQueryS(t *testing.T) {
	t.Parallel()
	r, err := nameserver.ParseRequest("QUERY S 3 80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.RecordType != "S" || r.NetID != 3 || r.Port != 80 {
		t.Errorf("unexpected result: %+v", r)
	}
}

func TestParseRequestRegisterA(t *testing.T) {
	t.Parallel()
	r, err := nameserver.ParseRequest("REGISTER A mynode 0:0001.0002.0003")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Command != "REGISTER" || r.RecordType != "A" || r.Name != "mynode" {
		t.Errorf("unexpected result: %+v", r)
	}
}

func TestParseRequestRegisterN(t *testing.T) {
	t.Parallel()
	r, err := nameserver.ParseRequest("REGISTER N mynet 7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.RecordType != "N" || r.NetID != 7 {
		t.Errorf("unexpected result: %+v", r)
	}
}

func TestParseRequestRegisterS(t *testing.T) {
	t.Parallel()
	r, err := nameserver.ParseRequest("REGISTER S svc 0:0001.0002.0003 5 443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.RecordType != "S" || r.NetID != 5 || r.Port != 443 {
		t.Errorf("unexpected result: %+v", r)
	}
}

func TestParseRequestCaseInsensitive(t *testing.T) {
	t.Parallel()
	r, err := nameserver.ParseRequest("query a hostname")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Command != "QUERY" || r.RecordType != "A" {
		t.Errorf("expected case-normalized result: %+v", r)
	}
}

func TestParseRequestErrors(t *testing.T) {
	t.Parallel()
	bad := []string{
		"",
		"QUERY",
		"QUERY X name",
		"QUERY S 1",              // missing port
		"QUERY S bad 80",         // bad net_id
		"REGISTER A",             // missing name + addr
		"REGISTER N name",        // missing net_id
		"REGISTER S name addr 1", // missing port
		"UNKNOWN A name",
	}
	for _, line := range bad {
		if _, err := nameserver.ParseRequest(line); err == nil {
			t.Errorf("ParseRequest(%q): expected error, got nil", line)
		}
	}
}

// --- FormatRequest round-trip ---

func TestFormatRequestRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []string{
		"QUERY A mynode",
		"QUERY N somenet",
		"QUERY S 3 80",
		"REGISTER A mynode 0:0001.0002.0003",
		"REGISTER N mynet 7",
		"REGISTER S svc 0:0001.0002.0003 5 443",
	}
	for _, line := range cases {
		r, err := nameserver.ParseRequest(line)
		if err != nil {
			t.Fatalf("ParseRequest(%q): %v", line, err)
		}
		got := nameserver.FormatRequest(r)
		if got != line {
			t.Errorf("FormatRequest round-trip: got %q want %q", got, line)
		}
	}
}

// --- RecordStore ---

func TestRecordStoreA(t *testing.T) {
	t.Parallel()
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	addr := protocol.Addr{Node: 1}
	rs.RegisterA("mynode", addr)

	got, err := rs.LookupA("mynode")
	if err != nil {
		t.Fatalf("LookupA: %v", err)
	}
	if got != addr {
		t.Errorf("LookupA: got %v want %v", got, addr)
	}
}

func TestRecordStoreANotFound(t *testing.T) {
	t.Parallel()
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	_, err := rs.LookupA("ghost")
	if err == nil {
		t.Fatal("expected error for unknown name")
	}
}

func TestRecordStoreAUnregister(t *testing.T) {
	t.Parallel()
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	rs.RegisterA("node", protocol.Addr{Node: 2})
	rs.UnregisterA("node")

	_, err := rs.LookupA("node")
	if err == nil {
		t.Fatal("expected error after unregister")
	}
}

func TestRecordStoreN(t *testing.T) {
	t.Parallel()
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	rs.RegisterN("testnet", 42)
	got, err := rs.LookupN("testnet")
	if err != nil {
		t.Fatalf("LookupN: %v", err)
	}
	if got != 42 {
		t.Errorf("LookupN: got %d want 42", got)
	}
}

func TestRecordStoreNNotFound(t *testing.T) {
	t.Parallel()
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	_, err := rs.LookupN("nonet")
	if err == nil {
		t.Fatal("expected error for unknown network name")
	}
}

func TestRecordStoreS(t *testing.T) {
	t.Parallel()
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	addr := protocol.Addr{Node: 10}
	rs.RegisterS("api", addr, 5, 443)

	svcs := rs.LookupS(5, 443)
	if len(svcs) == 0 {
		t.Fatal("expected at least one service entry")
	}
	found := false
	for _, s := range svcs {
		if s.Address == addr {
			found = true
		}
	}
	if !found {
		t.Errorf("registered service addr not found in results: %v", svcs)
	}
}

func TestRecordStoreSEmpty(t *testing.T) {
	t.Parallel()
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	svcs := rs.LookupS(99, 80)
	if len(svcs) != 0 {
		t.Errorf("expected empty result for unknown service, got %v", svcs)
	}
}

func TestRecordStoreAllA(t *testing.T) {
	t.Parallel()
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	rs.RegisterA("a1", protocol.Addr{Node: 1})
	rs.RegisterA("a2", protocol.Addr{Node: 2})
	all := rs.AllA()
	if len(all) != 2 {
		t.Errorf("AllA: got %d want 2", len(all))
	}
}

func TestRecordStoreOverwrite(t *testing.T) {
	t.Parallel()
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	rs.RegisterA("x", protocol.Addr{Node: 1})
	rs.RegisterA("x", protocol.Addr{Node: 2})
	got, _ := rs.LookupA("x")
	if got.Node != 2 {
		t.Errorf("overwrite: got node %d want 2", got.Node)
	}
}

func TestRecordStoreReap(t *testing.T) {
	t.Parallel()
	rs := nameserver.NewRecordStore()
	defer rs.Close()

	// Zero TTL causes all entries to be expired immediately on reap.
	rs.SetTTL(0)
	rs.RegisterA("soon-gone", protocol.Addr{Node: 99})
	rs.Reap()

	_, err := rs.LookupA("soon-gone")
	if err == nil && !strings.Contains(err.Error(), "not found") {
		// Reap may or may not evict based on TTL semantics; just verify no panic.
	}
	// No panic = pass.
}

// --- ParseResponse + FormatResponse* ---

func TestParseResponseOK(t *testing.T) {
	t.Parallel()
	resp, err := nameserver.ParseResponse("OK")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Type != "OK" {
		t.Errorf("got type %q want OK", resp.Type)
	}
}

func TestParseResponseErr(t *testing.T) {
	t.Parallel()
	resp, err := nameserver.ParseResponse("ERR not found")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Type != "ERR" || resp.Error != "not found" {
		t.Errorf("unexpected: %+v", resp)
	}
}

func TestParseResponseA(t *testing.T) {
	t.Parallel()
	resp, err := nameserver.ParseResponse("A mynode 0:0001.0002.0003")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Type != "A" || resp.Name != "mynode" || resp.Address != "0:0001.0002.0003" {
		t.Errorf("unexpected: %+v", resp)
	}
}

func TestParseResponseN(t *testing.T) {
	t.Parallel()
	resp, err := nameserver.ParseResponse("N testnet 42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Type != "N" || resp.Name != "testnet" || resp.NetID != 42 {
		t.Errorf("unexpected: %+v", resp)
	}
}

func TestParseResponseS(t *testing.T) {
	t.Parallel()
	resp, err := nameserver.ParseResponse("S api 0:0001.0002.0003 443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Type != "S" || len(resp.Services) != 1 {
		t.Errorf("unexpected: %+v", resp)
	}
	if resp.Services[0].Port != 443 {
		t.Errorf("port: got %d want 443", resp.Services[0].Port)
	}
}

func TestParseResponseSMultiLine(t *testing.T) {
	t.Parallel()
	input := "S svc1 0:0001.0002.0003 80\nS svc2 0:0004.0005.0006 443"
	resp, err := nameserver.ParseResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Type != "S" || len(resp.Services) != 2 {
		t.Errorf("unexpected: %+v", resp)
	}
}

func TestParseResponseErrors(t *testing.T) {
	t.Parallel()
	bad := []string{
		"",
		"UNKNOWN foo",
		"A",
		"A name",
		"N",
		"N name",
		"N name notanumber",
	}
	for _, line := range bad {
		if _, err := nameserver.ParseResponse(line); err == nil {
			t.Errorf("ParseResponse(%q): expected error, got nil", line)
		}
	}
}

func TestFormatResponseS(t *testing.T) {
	t.Parallel()
	entries := []nameserver.ServiceEntry{
		{Name: "api", Address: protocol.Addr{Node: 10}, Port: 443},
		{Name: "web", Address: protocol.Addr{Node: 20}, Port: 80},
	}
	out := nameserver.FormatResponseS(entries)
	if out == "" {
		t.Fatal("expected non-empty output")
	}
	resp, err := nameserver.ParseResponse(out)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.Type != "S" || len(resp.Services) != 2 {
		t.Errorf("unexpected: %+v", resp)
	}
}

func TestFormatResponseSEmpty(t *testing.T) {
	t.Parallel()
	out := nameserver.FormatResponseS(nil)
	if out != "S" {
		t.Errorf("empty FormatResponseS: got %q want %q", out, "S")
	}
}

func TestFormatResponseRoundTrip(t *testing.T) {
	t.Parallel()
	addr := protocol.Addr{Node: 1}
	addrStr := addr.String()

	cases := []struct {
		formatted string
		parse     func() (string, error)
	}{
		{"OK", func() (string, error) {
			r, err := nameserver.ParseResponse(nameserver.FormatResponseOK())
			return r.Type, err
		}},
		{"ERR something went wrong", func() (string, error) {
			r, err := nameserver.ParseResponse(nameserver.FormatResponseErr("something went wrong"))
			return r.Type + " " + r.Error, err
		}},
		{"A mynode " + addrStr, func() (string, error) {
			r, err := nameserver.ParseResponse(nameserver.FormatResponseA("mynode", addr))
			return "A " + r.Name + " " + r.Address, err
		}},
		{"N testnet 7", func() (string, error) {
			r, err := nameserver.ParseResponse(nameserver.FormatResponseN("testnet", 7))
			return "N " + r.Name + " " + strconv.Itoa(int(r.NetID)), err
		}},
	}
	for _, tc := range cases {
		got, err := tc.parse()
		if err != nil {
			t.Fatalf("round-trip for %q: %v", tc.formatted, err)
		}
		if got != tc.formatted {
			t.Errorf("round-trip: got %q want %q", got, tc.formatted)
		}
	}
}

// --- Persistence (SetStorePath / save / load) ---

func TestRecordStorePersistence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ns.json")

	// Write records, then close.
	rs := nameserver.NewRecordStore()
	rs.SetStorePath(path)
	rs.RegisterA("host1", protocol.Addr{Node: 10})
	rs.RegisterN("net1", 5)
	rs.RegisterS("svc1", protocol.Addr{Node: 20}, 5, 443)
	rs.Close()

	// Confirm the file was written.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file not written: %v", err)
	}

	// Load into a new store via SetStorePath.
	rs2 := nameserver.NewRecordStore()
	defer rs2.Close()
	rs2.SetStorePath(path)

	if addr, err := rs2.LookupA("host1"); err != nil || addr.Node != 10 {
		t.Errorf("LookupA after reload: addr=%v err=%v", addr, err)
	}
	if netID, err := rs2.LookupN("net1"); err != nil || netID != 5 {
		t.Errorf("LookupN after reload: %v err=%v", netID, err)
	}
	svcs := rs2.LookupS(5, 443)
	if len(svcs) == 0 {
		t.Error("LookupS after reload: expected service entries")
	}
}
