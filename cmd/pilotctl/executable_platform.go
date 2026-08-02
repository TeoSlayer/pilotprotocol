// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
)

// validateHostExecutable rejects a known native executable format built for a
// different host before it reaches the app supervisor. This is the fail-safe
// for legacy catalogue entries that predate per-platform bundle selection.
// Scripts and unrecognised adapter formats remain valid and are left to the OS.
func validateHostExecutable(path string) error {
	return validateExecutablePlatform(path, runtime.GOOS, runtime.GOARCH)
}

func validateExecutablePlatform(path, wantOS, wantArch string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open executable: %w", err)
	}
	defer f.Close()

	header := make([]byte, 32)
	n, err := f.Read(header)
	if err != nil && n == 0 {
		return fmt.Errorf("read executable header: %w", err)
	}
	header = header[:n]
	if len(header) >= 2 && string(header[:2]) == "#!" {
		return nil
	}
	if len(header) >= 20 && string(header[:4]) == "\x7fELF" {
		if wantOS != "linux" {
			return fmt.Errorf("binary format is ELF/Linux, host is %s/%s", wantOS, wantArch)
		}
		var order binary.ByteOrder
		switch header[5] {
		case 1:
			order = binary.LittleEndian
		case 2:
			order = binary.BigEndian
		default:
			return fmt.Errorf("ELF header has invalid byte order %d", header[5])
		}
		machine := order.Uint16(header[18:20])
		if !elfMachineMatches(machine, wantArch) {
			return fmt.Errorf("ELF machine %d does not match host architecture %s", machine, wantArch)
		}
		return nil
	}

	if len(header) >= 8 {
		magic := binary.BigEndian.Uint32(header[:4])
		var order binary.ByteOrder
		switch magic {
		case 0xfeedface, 0xfeedfacf:
			order = binary.BigEndian
		case 0xcefaedfe, 0xcffaedfe:
			order = binary.LittleEndian
		}
		if order != nil {
			if wantOS != "darwin" {
				return fmt.Errorf("binary format is Mach-O/macOS, host is %s/%s", wantOS, wantArch)
			}
			cpu := order.Uint32(header[4:8])
			if !machCPUMatches(cpu, wantArch) {
				return fmt.Errorf("Mach-O CPU %#x does not match host architecture %s", cpu, wantArch)
			}
		}
	}
	return nil
}

func elfMachineMatches(machine uint16, arch string) bool {
	switch arch {
	case "amd64":
		return machine == 62 // EM_X86_64
	case "arm64":
		return machine == 183 // EM_AARCH64
	default:
		return false
	}
}

func machCPUMatches(cpu uint32, arch string) bool {
	switch arch {
	case "amd64":
		return cpu == 0x01000007
	case "arm64":
		return cpu == 0x0100000c
	default:
		return false
	}
}
