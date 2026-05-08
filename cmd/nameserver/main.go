// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/config"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/logging"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/plugins/nameserver"
)

// driverPortListener wraps *driver.Driver so its Listen method satisfies
// nameserver.PortListener (returns net.Listener rather than *driver.Listener).
type driverPortListener struct{ d *driver.Driver }

func (w driverPortListener) Listen(port uint16) (net.Listener, error) {
	return w.d.Listen(port)
}

// driverDialer wraps *driver.Driver so DialAddrTimeout returns net.Conn,
// satisfying nameserver.Dialer without importing pkg/driver from within the plugin.
type driverDialer struct{ d *driver.Driver }

func (w driverDialer) DialAddrTimeout(dst protocol.Addr, port uint16, timeout time.Duration) (net.Conn, error) {
	return w.d.DialAddrTimeout(dst, port, timeout)
}

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

	ns := nameserver.New(driverPortListener{d}, *storePath)
	log.Fatal(ns.ListenAndServe())
}
