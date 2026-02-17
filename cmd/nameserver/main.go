package main

import (
	"flag"
	"log"

	"github.com/TeoSlayer/pilotprotocol/pkg/config"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/logging"
	"github.com/TeoSlayer/pilotprotocol/pkg/nameserver"
)

func main() {
	log.Fatal("nameserver is currently disabled (WIP). Use hostname-based discovery via the registry instead.")

	configPath := flag.String("config", "", "path to config file (JSON)")
	socketPath := flag.String("socket", "/tmp/pilot.sock", "daemon socket path")
	storePath := flag.String("store", "", "path to persist nameserver records (JSON)")
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

	d, err := driver.Connect(*socketPath)
	if err != nil {
		log.Fatalf("connect to daemon: %v", err)
	}
	defer d.Close()

	ns := nameserver.New(d, *storePath)
	log.Fatal(ns.ListenAndServe())
}
