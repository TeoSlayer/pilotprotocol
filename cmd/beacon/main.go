package main

import (
	"flag"
	"log"

	"web4/pkg/beacon"
	"web4/pkg/config"
	"web4/pkg/logging"
)

func main() {
	configPath := flag.String("config", "", "path to config file (JSON)")
	addr := flag.String("addr", ":9001", "listen address (UDP)")
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

	s := beacon.New()
	log.Fatal(s.ListenAndServe(*addr))
}
