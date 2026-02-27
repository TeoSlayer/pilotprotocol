package pilot_dashboard

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/tests"
)

// TestRunDashboardWithSeed is a manual test that starts a local rendezvous server,
// seeds it with test data, and keeps it running for manual dashboard inspection.
//
// Run with: go test -v -run TestRunDashboardWithSeed -timeout=0 ./tests/pilot_dashboard
//
// The dashboard will be available at: http://127.0.0.1:8080
// Press Ctrl+C to stop the server.
func TestRunDashboardWithSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping manual dashboard test in short mode")
	}

	log.Println("Starting rendezvous server with dashboard...")

	// Create test environment with dashboard enabled
	env := tests.NewTestEnv(t)

	// Start dashboard on the registry
	dashboardAddr := "127.0.0.1:8080"
	go func() {
		if err := env.Registry.ServeDashboard(dashboardAddr); err != nil {
			log.Printf("dashboard error: %v", err)
		}
	}()

	// Wait a bit for dashboard to start
	time.Sleep(500 * time.Millisecond)

	// Seed the registry with test data
	log.Println("\nSeeding registry with test data...")
	if err := SeedRegistry(env.RegistryAddr); err != nil {
		t.Fatalf("failed to seed registry: %v", err)
	}

	// Print access information
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Printf("✅ Dashboard is running!\n\n")
	fmt.Printf("   Dashboard URL:  http://%s\n", dashboardAddr)
	fmt.Printf("   Registry Addr:  %s\n", env.RegistryAddr)
	fmt.Printf("   Beacon Addr:    %s\n\n", env.BeaconAddr)
	fmt.Println("   Press Ctrl+C to stop the server")
	fmt.Println(strings.Repeat("=", 70) + "\n")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("\nShutting down...")
}
