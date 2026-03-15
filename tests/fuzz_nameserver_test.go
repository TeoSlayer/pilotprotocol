package tests

import (
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/nameserver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ---------------------------------------------------------------------------
// Fuzz targets
// ---------------------------------------------------------------------------

func FuzzParseRequest(f *testing.F) {
	f.Add("QUERY A myhost")
	f.Add("QUERY N mynet")
	f.Add("QUERY S 1 80")
	f.Add("REGISTER A myhost 0:0000.0000.0001")
	f.Add("REGISTER N mynet 1")
	f.Add("REGISTER S myhost 0:0000.0000.0001 1 80")
	f.Add("")
	f.Add("SINGLE")
	f.Add(strings.Repeat("X", 10000))

	f.Fuzz(func(t *testing.T, line string) {
		_, _ = nameserver.ParseRequest(line)
	})
}

func FuzzParseResponse(f *testing.F) {
	f.Add("OK")
	f.Add("ERR not found")
	f.Add("A myhost 0:0000.0000.0001")
	f.Add("N mynet 1")
	f.Add("S myhost 0:0000.0000.0001 80")
	f.Add("")
	f.Add("UNKNOWN stuff")

	f.Fuzz(func(t *testing.T, text string) {
		_, _ = nameserver.ParseResponse(text)
	})
}

func FuzzNameserverRequestRoundTrip(f *testing.F) {
	f.Add("QUERY", "A", "myhost", "", uint16(0), uint16(0))
	f.Add("QUERY", "N", "mynet", "", uint16(0), uint16(0))
	f.Add("QUERY", "S", "", "", uint16(1), uint16(80))
	f.Add("REGISTER", "A", "myhost", "0:0000.0000.0001", uint16(0), uint16(0))
	f.Add("REGISTER", "N", "mynet", "", uint16(1), uint16(0))
	f.Add("REGISTER", "S", "myhost", "0:0000.0000.0001", uint16(1), uint16(80))

	f.Fuzz(func(t *testing.T, cmd, rt, name, addr string, netID, port uint16) {
		cmd = strings.ToUpper(cmd)
		rt = strings.ToUpper(rt)
		if cmd != "QUERY" && cmd != "REGISTER" {
			return
		}
		if rt != "A" && rt != "N" && rt != "S" {
			return
		}
		// Skip strings with whitespace (would break field parsing)
		for _, s := range []string{name, addr} {
			if strings.ContainsAny(s, " \t\n\r") {
				return
			}
		}
		if name == "" && (rt == "A" || rt == "N") {
			return
		}

		req := nameserver.Request{
			Command:    cmd,
			RecordType: rt,
			Name:       name,
			Address:    addr,
			NetID:      netID,
			Port:       port,
		}

		wire := nameserver.FormatRequest(req)
		if wire == "" {
			return
		}

		parsed, err := nameserver.ParseRequest(wire)
		if err != nil {
			// Some inputs are not parseable (e.g. empty names) — that's OK
			return
		}

		if parsed.Command != cmd {
			t.Errorf("command: %q != %q", parsed.Command, cmd)
		}
		if parsed.RecordType != rt {
			t.Errorf("record type: %q != %q", parsed.RecordType, rt)
		}
	})
}

// ---------------------------------------------------------------------------
// Edge case unit tests
// ---------------------------------------------------------------------------

func TestParseRequestEmpty(t *testing.T) {
	_, err := nameserver.ParseRequest("")
	if err == nil {
		t.Fatal("expected error for empty request")
	}
}

func TestParseRequestWhitespace(t *testing.T) {
	_, err := nameserver.ParseRequest("   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only request")
	}
}

func TestParseRequestSingleWord(t *testing.T) {
	_, err := nameserver.ParseRequest("QUERY")
	if err == nil {
		t.Fatal("expected error for single-word request")
	}
}

func TestParseRequestUnknownCommand(t *testing.T) {
	_, err := nameserver.ParseRequest("DELETE A foo")
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestParseRequestUnknownRecordType(t *testing.T) {
	_, err := nameserver.ParseRequest("QUERY X foo")
	if err == nil {
		t.Fatal("expected error for unknown record type")
	}
}

func TestParseRequestExtraFields(t *testing.T) {
	// Extra fields should be ignored (or at least not crash)
	req, err := nameserver.ParseRequest("QUERY A myhost extra1 extra2")
	if err != nil {
		t.Fatalf("ParseRequest with extra fields: %v", err)
	}
	if req.Name != "myhost" {
		t.Fatalf("expected name 'myhost', got %q", req.Name)
	}
}

func TestParseRequestQuerySOverflow(t *testing.T) {
	_, err := nameserver.ParseRequest("QUERY S 65536 80")
	if err == nil {
		t.Fatal("expected error for net_id overflow")
	}
}

func TestParseRequestRegisterSBoundary(t *testing.T) {
	req, err := nameserver.ParseRequest("REGISTER S svc 0:0000.0000.0001 65535 65535")
	if err != nil {
		t.Fatalf("ParseRequest boundary: %v", err)
	}
	if req.NetID != 65535 || req.Port != 65535 {
		t.Fatalf("boundary values: netID=%d port=%d", req.NetID, req.Port)
	}
}

func TestParseResponseEmpty(t *testing.T) {
	_, err := nameserver.ParseResponse("")
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}

func TestParseResponseOK(t *testing.T) {
	resp, err := nameserver.ParseResponse("OK")
	if err != nil {
		t.Fatalf("ParseResponse OK: %v", err)
	}
	if resp.Type != "OK" {
		t.Fatalf("expected type OK, got %q", resp.Type)
	}
}

func TestParseResponseERRNoMessage(t *testing.T) {
	resp, err := nameserver.ParseResponse("ERR")
	if err != nil {
		t.Fatalf("ParseResponse ERR: %v", err)
	}
	if resp.Type != "ERR" {
		t.Fatalf("expected type ERR, got %q", resp.Type)
	}
}

func TestParseResponseERRWithMessage(t *testing.T) {
	resp, err := nameserver.ParseResponse("ERR something went wrong")
	if err != nil {
		t.Fatalf("ParseResponse ERR msg: %v", err)
	}
	if resp.Type != "ERR" {
		t.Fatalf("expected type ERR, got %q", resp.Type)
	}
	if resp.Error != "something went wrong" {
		t.Fatalf("error: %q", resp.Error)
	}
}

func TestParseResponseSMalformedAddr(t *testing.T) {
	// S response with bad address — should silently skip/zero
	resp, err := nameserver.ParseResponse("S myhost not-an-addr 80")
	if err != nil {
		t.Fatalf("ParseResponse S malformed: %v", err)
	}
	if resp.Type != "S" {
		t.Fatalf("expected type S, got %q", resp.Type)
	}
	// The entry should still be added (addr parsed as zero, port parsed as 80)
	if len(resp.Services) != 1 {
		t.Fatalf("expected 1 service entry, got %d", len(resp.Services))
	}
}

func TestParseResponseSMalformedPort(t *testing.T) {
	resp, err := nameserver.ParseResponse("S myhost 0:0000.0000.0001 not-a-port")
	if err != nil {
		t.Fatalf("ParseResponse S bad port: %v", err)
	}
	if len(resp.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(resp.Services))
	}
	// Port should be 0 (parse error → silently zero)
	if resp.Services[0].Port != 0 {
		t.Fatalf("expected port 0 for bad port, got %d", resp.Services[0].Port)
	}
}

func TestFormatRequestRoundTrips(t *testing.T) {
	tests := []struct {
		req  nameserver.Request
		want string
	}{
		{nameserver.Request{Command: "QUERY", RecordType: "A", Name: "myhost"}, "QUERY A myhost"},
		{nameserver.Request{Command: "QUERY", RecordType: "N", Name: "mynet"}, "QUERY N mynet"},
		{nameserver.Request{Command: "QUERY", RecordType: "S", NetID: 1, Port: 80}, "QUERY S 1 80"},
		{nameserver.Request{Command: "REGISTER", RecordType: "A", Name: "myhost", Address: "0:0000.0000.0001"}, "REGISTER A myhost 0:0000.0000.0001"},
		{nameserver.Request{Command: "REGISTER", RecordType: "N", Name: "mynet", NetID: 42}, "REGISTER N mynet 42"},
		{nameserver.Request{Command: "REGISTER", RecordType: "S", Name: "svc", Address: "0:0000.0000.0001", NetID: 1, Port: 80}, "REGISTER S svc 0:0000.0000.0001 1 80"},
	}

	for _, tc := range tests {
		got := nameserver.FormatRequest(tc.req)
		if got != tc.want {
			t.Errorf("FormatRequest: %q != %q", got, tc.want)
		}
		parsed, err := nameserver.ParseRequest(got)
		if err != nil {
			t.Errorf("ParseRequest(%q): %v", got, err)
			continue
		}
		if parsed.Command != tc.req.Command || parsed.RecordType != tc.req.RecordType {
			t.Errorf("round-trip mismatch for %q", got)
		}
	}
}

func TestFormatResponseRoundTrips(t *testing.T) {
	// A record
	aResp := nameserver.FormatResponseA("myhost", protocol.Addr{Network: 1, Node: 10})
	parsed, err := nameserver.ParseResponse(aResp)
	if err != nil {
		t.Fatalf("ParseResponse A: %v", err)
	}
	if parsed.Type != "A" || parsed.Name != "myhost" {
		t.Fatalf("A response: type=%q name=%q", parsed.Type, parsed.Name)
	}

	// N record
	nResp := nameserver.FormatResponseN("mynet", 42)
	parsed, err = nameserver.ParseResponse(nResp)
	if err != nil {
		t.Fatalf("ParseResponse N: %v", err)
	}
	if parsed.Type != "N" || parsed.Name != "mynet" || parsed.NetID != 42 {
		t.Fatalf("N response: type=%q name=%q netID=%d", parsed.Type, parsed.Name, parsed.NetID)
	}

	// S record
	entries := []nameserver.ServiceEntry{
		{Name: "svc1", Address: protocol.Addr{Network: 1, Node: 10}, Port: 80},
		{Name: "svc2", Address: protocol.Addr{Network: 1, Node: 20}, Port: 443},
	}
	sResp := nameserver.FormatResponseS(entries)
	parsed, err = nameserver.ParseResponse(sResp)
	if err != nil {
		t.Fatalf("ParseResponse S: %v", err)
	}
	if parsed.Type != "S" || len(parsed.Services) != 2 {
		t.Fatalf("S response: type=%q services=%d", parsed.Type, len(parsed.Services))
	}

	// Empty S
	emptyS := nameserver.FormatResponseS(nil)
	if emptyS != "S" {
		t.Fatalf("empty S: %q", emptyS)
	}

	// OK
	okResp := nameserver.FormatResponseOK()
	parsed, err = nameserver.ParseResponse(okResp)
	if err != nil {
		t.Fatalf("ParseResponse OK: %v", err)
	}
	if parsed.Type != "OK" {
		t.Fatalf("OK response: type=%q", parsed.Type)
	}

	// ERR
	errResp := nameserver.FormatResponseErr("bad request")
	parsed, err = nameserver.ParseResponse(errResp)
	if err != nil {
		t.Fatalf("ParseResponse ERR: %v", err)
	}
	if parsed.Type != "ERR" || parsed.Error != "bad request" {
		t.Fatalf("ERR response: type=%q error=%q", parsed.Type, parsed.Error)
	}
}

func TestParseRequestCaseInsensitive(t *testing.T) {
	// Lowercase commands should work
	req, err := nameserver.ParseRequest("query a myhost")
	if err != nil {
		t.Fatalf("lowercase query: %v", err)
	}
	if req.Command != "QUERY" || req.RecordType != "A" {
		t.Fatalf("expected QUERY A, got %s %s", req.Command, req.RecordType)
	}
}

func TestParseResponseUnknownType(t *testing.T) {
	_, err := nameserver.ParseResponse("UNKNOWN stuff")
	if err == nil {
		t.Fatal("expected error for unknown response type")
	}
}

func TestParseRequestRegisterAMissingFields(t *testing.T) {
	_, err := nameserver.ParseRequest("REGISTER A myhost")
	if err == nil {
		t.Fatal("expected error for REGISTER A missing address")
	}
}

func TestParseRequestRegisterNMissingFields(t *testing.T) {
	_, err := nameserver.ParseRequest("REGISTER N mynet")
	if err == nil {
		t.Fatal("expected error for REGISTER N missing net_id")
	}
}

func TestParseRequestRegisterSMissingFields(t *testing.T) {
	_, err := nameserver.ParseRequest("REGISTER S svc 0:0000.0000.0001 1")
	if err == nil {
		t.Fatal("expected error for REGISTER S missing port")
	}
}

func TestParseRequestQuerySPortOverflow(t *testing.T) {
	_, err := nameserver.ParseRequest("QUERY S 1 99999")
	if err == nil {
		t.Fatal("expected error for port overflow")
	}
}

func TestParseRequestInvalidNetID(t *testing.T) {
	_, err := nameserver.ParseRequest("REGISTER N mynet abc")
	if err == nil {
		t.Fatal("expected error for non-numeric net_id")
	}
}
