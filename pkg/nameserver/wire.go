package nameserver

import (
	"fmt"
	"strconv"
	"strings"

	"web4/pkg/protocol"
)

// Wire protocol for the nameserver. Plain text, newline-delimited.
//
// Requests:
//   QUERY A <name>
//   QUERY N <name>
//   QUERY S <net_id> <port>
//   REGISTER A <name> <address>
//   REGISTER N <name> <net_id>
//   REGISTER S <name> <address> <net_id> <port>
//
// Responses:
//   A <name> <address>
//   N <name> <net_id>
//   S <name> <address> <port>   (repeated, blank line terminates)
//   OK
//   ERR <message>

// Request is a parsed nameserver request.
type Request struct {
	Command    string // "QUERY" or "REGISTER"
	RecordType string // "A", "N", "S"
	Name       string
	Address    string // for A and S
	NetID      uint16 // for N and S
	Port       uint16 // for S
}

// Response is a nameserver response.
type Response struct {
	Type     string // "A", "N", "S", "OK", "ERR"
	Name     string
	Address  string
	NetID    uint16
	Port     uint16
	Services []ServiceEntry // for S responses
	Error    string         // for ERR responses
}

// ParseRequest parses a plain-text nameserver request.
func ParseRequest(line string) (Request, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Request{}, fmt.Errorf("too few fields")
	}

	cmd := strings.ToUpper(fields[0])
	rt := strings.ToUpper(fields[1])

	switch cmd {
	case "QUERY":
		switch rt {
		case "A":
			if len(fields) < 3 {
				return Request{}, fmt.Errorf("QUERY A requires <name>")
			}
			return Request{Command: cmd, RecordType: rt, Name: fields[2]}, nil
		case "N":
			if len(fields) < 3 {
				return Request{}, fmt.Errorf("QUERY N requires <name>")
			}
			return Request{Command: cmd, RecordType: rt, Name: fields[2]}, nil
		case "S":
			if len(fields) < 4 {
				return Request{}, fmt.Errorf("QUERY S requires <net_id> <port>")
			}
			netID, err := strconv.ParseUint(fields[2], 10, 16)
			if err != nil {
				return Request{}, fmt.Errorf("invalid net_id: %w", err)
			}
			port, err := strconv.ParseUint(fields[3], 10, 16)
			if err != nil {
				return Request{}, fmt.Errorf("invalid port: %w", err)
			}
			return Request{Command: cmd, RecordType: rt, NetID: uint16(netID), Port: uint16(port)}, nil
		default:
			return Request{}, fmt.Errorf("unknown record type: %s", rt)
		}

	case "REGISTER":
		switch rt {
		case "A":
			if len(fields) < 4 {
				return Request{}, fmt.Errorf("REGISTER A requires <name> <address>")
			}
			return Request{Command: cmd, RecordType: rt, Name: fields[2], Address: fields[3]}, nil
		case "N":
			if len(fields) < 4 {
				return Request{}, fmt.Errorf("REGISTER N requires <name> <net_id>")
			}
			netID, err := strconv.ParseUint(fields[3], 10, 16)
			if err != nil {
				return Request{}, fmt.Errorf("invalid net_id: %w", err)
			}
			return Request{Command: cmd, RecordType: rt, Name: fields[2], NetID: uint16(netID)}, nil
		case "S":
			if len(fields) < 6 {
				return Request{}, fmt.Errorf("REGISTER S requires <name> <address> <net_id> <port>")
			}
			netID, err := strconv.ParseUint(fields[4], 10, 16)
			if err != nil {
				return Request{}, fmt.Errorf("invalid net_id: %w", err)
			}
			port, err := strconv.ParseUint(fields[5], 10, 16)
			if err != nil {
				return Request{}, fmt.Errorf("invalid port: %w", err)
			}
			return Request{Command: cmd, RecordType: rt, Name: fields[2], Address: fields[3], NetID: uint16(netID), Port: uint16(port)}, nil
		default:
			return Request{}, fmt.Errorf("unknown record type: %s", rt)
		}

	default:
		return Request{}, fmt.Errorf("unknown command: %s", cmd)
	}
}

// FormatRequest serializes a request to wire format.
func FormatRequest(r Request) string {
	switch r.RecordType {
	case "A":
		if r.Command == "REGISTER" {
			return fmt.Sprintf("%s A %s %s", r.Command, r.Name, r.Address)
		}
		return fmt.Sprintf("%s A %s", r.Command, r.Name)
	case "N":
		if r.Command == "REGISTER" {
			return fmt.Sprintf("%s N %s %d", r.Command, r.Name, r.NetID)
		}
		return fmt.Sprintf("%s N %s", r.Command, r.Name)
	case "S":
		if r.Command == "REGISTER" {
			return fmt.Sprintf("%s S %s %s %d %d", r.Command, r.Name, r.Address, r.NetID, r.Port)
		}
		return fmt.Sprintf("%s S %d %d", r.Command, r.NetID, r.Port)
	}
	return ""
}

// ParseResponse parses a plain-text nameserver response.
func ParseResponse(text string) (Response, error) {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) == 0 {
		return Response{}, fmt.Errorf("empty response")
	}

	first := strings.TrimSpace(lines[0])
	if first == "OK" {
		return Response{Type: "OK"}, nil
	}

	fields := strings.Fields(first)
	if len(fields) < 1 {
		return Response{}, fmt.Errorf("empty response line")
	}

	switch fields[0] {
	case "ERR":
		msg := strings.TrimPrefix(first, "ERR ")
		return Response{Type: "ERR", Error: msg}, nil

	case "A":
		if len(fields) < 3 {
			return Response{}, fmt.Errorf("invalid A response")
		}
		return Response{Type: "A", Name: fields[1], Address: fields[2]}, nil

	case "N":
		if len(fields) < 3 {
			return Response{}, fmt.Errorf("invalid N response")
		}
		netID, err := strconv.ParseUint(fields[2], 10, 16)
		if err != nil {
			return Response{}, fmt.Errorf("invalid net_id: %w", err)
		}
		return Response{Type: "N", Name: fields[1], NetID: uint16(netID)}, nil

	case "S":
		// Multiple S lines
		var entries []ServiceEntry
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 4 || f[0] != "S" {
				continue
			}
			addr, _ := protocol.ParseAddr(f[2])
			port, _ := strconv.ParseUint(f[3], 10, 16)
			entries = append(entries, ServiceEntry{Name: f[1], Address: addr, Port: uint16(port)})
		}
		return Response{Type: "S", Services: entries}, nil

	default:
		return Response{}, fmt.Errorf("unknown response type: %s", fields[0])
	}
}

// FormatResponseA formats an A record response.
func FormatResponseA(name string, addr protocol.Addr) string {
	return fmt.Sprintf("A %s %s", name, addr.String())
}

// FormatResponseN formats an N record response.
func FormatResponseN(name string, netID uint16) string {
	return fmt.Sprintf("N %s %d", name, netID)
}

// FormatResponseS formats S record responses (one line per entry).
func FormatResponseS(entries []ServiceEntry) string {
	if len(entries) == 0 {
		return "S"
	}
	var lines []string
	for _, e := range entries {
		lines = append(lines, fmt.Sprintf("S %s %s %d", e.Name, e.Address.String(), e.Port))
	}
	return strings.Join(lines, "\n")
}

// FormatResponseOK formats a success response.
func FormatResponseOK() string {
	return "OK"
}

// FormatResponseErr formats an error response.
func FormatResponseErr(msg string) string {
	return fmt.Sprintf("ERR %s", msg)
}
