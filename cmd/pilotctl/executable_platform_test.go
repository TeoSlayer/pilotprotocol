// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExecutableHeader(t *testing.T, header []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app")
	if err := os.WriteFile(path, header, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateExecutablePlatformRejectsWrongOSAndArchitecture(t *testing.T) {
	t.Parallel()
	elf := make([]byte, 32)
	copy(elf, "\x7fELF")
	elf[5] = 1
	binary.LittleEndian.PutUint16(elf[18:20], 62)
	elfPath := writeExecutableHeader(t, elf)
	if err := validateExecutablePlatform(elfPath, "linux", "amd64"); err != nil {
		t.Fatalf("matching ELF rejected: %v", err)
	}
	if err := validateExecutablePlatform(elfPath, "darwin", "amd64"); err == nil || !strings.Contains(err.Error(), "ELF/Linux") {
		t.Fatalf("ELF on Darwin error = %v", err)
	}
	if err := validateExecutablePlatform(elfPath, "linux", "arm64"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("amd64 ELF on arm64 error = %v", err)
	}

	mach := make([]byte, 32)
	binary.LittleEndian.PutUint32(mach[:4], 0xfeedfacf)
	binary.LittleEndian.PutUint32(mach[4:8], 0x0100000c)
	machPath := writeExecutableHeader(t, mach)
	if err := validateExecutablePlatform(machPath, "darwin", "arm64"); err != nil {
		t.Fatalf("matching Mach-O rejected: %v", err)
	}
	if err := validateExecutablePlatform(machPath, "linux", "arm64"); err == nil || !strings.Contains(err.Error(), "Mach-O/macOS") {
		t.Fatalf("Mach-O on Linux error = %v", err)
	}
}

func TestValidateExecutablePlatformAllowsScriptsAndUnknownAdapters(t *testing.T) {
	t.Parallel()
	for _, content := range [][]byte{[]byte("#!/bin/sh\nexit 0\n"), []byte("adapter-v1\n")} {
		if err := validateExecutablePlatform(writeExecutableHeader(t, content), "linux", "amd64"); err != nil {
			t.Fatalf("non-native executable rejected: %v", err)
		}
	}
}
