package main

import (
	"flag"
	"log"

	"web4/pkg/config"
	"web4/pkg/logging"
	"web4/pkg/registry"
)

func main() {
	configPath := flag.String("config", "", "path to config file (JSON)")
	addr := flag.String("addr", ":9000", "listen address")
	beacon := flag.String("beacon", "34.71.57.205:9001", "beacon server address")
	storePath := flag.String("store", "", "path to persist registry state (JSON snapshot)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (empty = auto self-signed)")
	tlsKey := flag.String("tls-key", "", "TLS key file")
	enableTLS := flag.Bool("tls", false, "enable TLS for registry connections")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", "text", "log format (text, json)")
	adminToken := flag.String("admin-token", "", "admin token for network creation (empty = creation disabled)")
	flag.Parse()

	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		config.ApplyToFlags(cfg)
	}

	logging.Setup(*logLevel, *logFormat)

	s := registry.NewWithStore(*beacon, *storePath)
	if *adminToken != "" {
		s.SetAdminToken(*adminToken)
	}
	if *enableTLS {
		if err := s.SetTLS(*tlsCert, *tlsKey); err != nil {
			log.Fatalf("TLS setup: %v", err)
		}
	}
	log.Fatal(s.ListenAndServe(*addr))
}
