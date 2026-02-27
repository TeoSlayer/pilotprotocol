//go:build ignore
// +build ignore

package main

import (
	"log"
	"os"

	"github.com/TeoSlayer/pilotprotocol/tests/pilot_dashboard"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run seed_dashboard_main.go <registry-address>\nExample: go run seed_dashboard_main.go 127.0.0.1:9001")
	}

	registryAddr := os.Args[1]
	if err := pilot_dashboard.SeedRegistry(registryAddr); err != nil {
		log.Fatalf("failed to seed registry: %v", err)
	}
}
