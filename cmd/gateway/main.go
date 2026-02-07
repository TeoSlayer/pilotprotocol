package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"web4/pkg/config"
	"web4/pkg/gateway"
	"web4/pkg/logging"
	"web4/pkg/protocol"
)

func main() {
	configPath := flag.String("config", "", "path to config file (JSON)")
	socketPath := flag.String("socket", "/tmp/pilot.sock", "daemon socket path")
	subnet := flag.String("subnet", "10.4.0.0/16", "local IP subnet for mappings")
	portsStr := flag.String("ports", "", "comma-separated ports to proxy (default: 80,443,1000,1001,1002,7,8080,8443)")
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

	args := flag.Args()
	if len(args) < 1 {
		usage()
	}

	var ports []uint16
	if *portsStr != "" {
		for _, s := range strings.Split(*portsStr, ",") {
			s = strings.TrimSpace(s)
			p, err := strconv.ParseUint(s, 10, 16)
			if err != nil {
				log.Fatalf("invalid port %q: %v", s, err)
			}
			ports = append(ports, uint16(p))
		}
	}

	gw, err := gateway.New(gateway.Config{
		Subnet:     *subnet,
		SocketPath: *socketPath,
		Ports:      ports,
	})
	if err != nil {
		log.Fatalf("create gateway: %v", err)
	}

	switch args[0] {
	case "run":
		cmdRun(gw, args[1:])
	case "map":
		if err := gw.Start(); err != nil {
			log.Fatalf("start: %v", err)
		}
		cmdMap(gw, args[1:])
	default:
		usage()
	}
}

func cmdRun(gw *gateway.Gateway, args []string) {
	if err := gw.Start(); err != nil {
		log.Fatalf("start gateway: %v", err)
	}

	// Map any addresses passed as arguments: <pilot-addr> [<local-ip>]
	for i := 0; i < len(args); i += 2 {
		pilotAddrStr := args[i]
		var localIP string
		if i+1 < len(args) {
			// Check if next arg looks like an IP
			if p := net.ParseIP(args[i+1]); p != nil {
				localIP = args[i+1]
			} else {
				i-- // not an IP, it's the next pilot address
			}
		}

		pilotAddr, err := protocol.ParseAddr(pilotAddrStr)
		if err != nil {
			log.Fatalf("parse address %s: %v", pilotAddrStr, err)
		}

		assigned, err := gw.Map(pilotAddr, localIP)
		if err != nil {
			log.Fatalf("map %s: %v", pilotAddrStr, err)
		}
		fmt.Printf("mapped %s → %s\n", assigned, pilotAddr)
	}

	slog.Info("gateway running")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	gw.Stop()
	slog.Info("gateway stopped")
}

func cmdMap(gw *gateway.Gateway, args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: gateway map <pilot-addr> [<local-ip>]\n")
		os.Exit(1)
	}

	pilotAddr, err := protocol.ParseAddr(args[0])
	if err != nil {
		log.Fatalf("parse address: %v", err)
	}

	var localIP string
	if len(args) > 1 {
		localIP = args[1]
	}

	assigned, err := gw.Map(pilotAddr, localIP)
	if err != nil {
		log.Fatalf("map: %v", err)
	}
	fmt.Printf("%s → %s\n", assigned, pilotAddr)
}

func usage() {
	fmt.Fprintf(os.Stderr, `gateway — Pilot Protocol IP bridge

Usage:
  gateway run [<pilot-addr> [<local-ip>]] ...   Start gateway with mappings
  gateway map <pilot-addr> [<local-ip>]          Add a mapping

Flags:
  -socket    Daemon socket path (default: /tmp/pilot.sock)
  -subnet    Local IP subnet (default: 10.4.0.0/16)
  -ports     Comma-separated ports to proxy (default: 80,443,1000,1001,1002,7,8080,8443)
`)
	os.Exit(1)
}
