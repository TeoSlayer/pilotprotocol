// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/TeoSlayer/pilotprotocol/pkg/beacon"
	"github.com/TeoSlayer/pilotprotocol/pkg/config"
	"github.com/TeoSlayer/pilotprotocol/pkg/logging"
)

func main() {
	configPath := flag.String("config", "", "path to config file (JSON)")
	addr := flag.String("addr", ":9001", "listen address (UDP)")
	advertiseAddr := flag.String("advertise-addr", "", "address to register with the registry (e.g. 34.71.57.205:9001). When unset, the beacon auto-detects its outbound IP from the TCP connection to the registry — which yields the INTERNAL VPC address on GCP MIG deployments and is unreachable from external daemons. MIG-deployed beacons MUST set this to the public rendezvous DNAT entrypoint.")
	beaconID := flag.Uint("beacon-id", 0, "unique beacon ID (0 = standalone)")
	peersFlag := flag.String("peers", "", "comma-separated peer beacon addresses for gossip")
	healthAddr := flag.String("health", "", "health check HTTP address (e.g. :8080)")
	registryAddr := flag.String("registry", "", "registry address for dynamic peer discovery (e.g. 10.128.0.12:9000)")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	flag.Parse()

	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		config.ApplyToFlags(cfg)
	}

	logging.Setup(*logLevel, *logFormat)

	var peers []string
	if *peersFlag != "" {
		for _, p := range strings.Split(*peersFlag, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				peers = append(peers, p)
			}
		}
	}

	s := beacon.NewWithPeers(uint32(*beaconID), peers)

	if *registryAddr != "" {
		s.SetRegistry(*registryAddr)
	}
	if *advertiseAddr != "" {
		s.SetAdvertiseAddr(*advertiseAddr)
	}

	if *healthAddr != "" {
		go func() {
			if err := s.ServeHealth(*healthAddr); err != nil {
				slog.Error("health endpoint failed", "err", err)
			}
		}()
	}

	go func() {
		if err := s.ListenAndServe(*addr); err != nil {
			log.Fatalf("beacon: %v", err)
		}
	}()

	slog.Info("beacon running", "addr", *addr, "beacon_id", *beaconID, "peers", len(peers), "registry", *registryAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	slog.Info("shutting down")
	s.Close()
}
