// responder is a cron-based daemon that polls the pilot inbox, dispatches
// recognised commands to local HTTP services, and sends the responses back
// to the originating node.
//
// Startup fails immediately if ~/.pilot/endpoints.yaml is missing or invalid.
//
// Usage:
//
//	responder [-config <path>] [-interval <duration>] [-socket <path>]
//
// Endpoints are configured in ~/.pilot/endpoints.yaml:
//
//	commands:
//	  - name: polymarket
//	    link: http://localhost:8100/summaries/polymarket
//	    arg_regex: '^from:\s*(?P<from>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)(?:\s*,\s*to:\s*(?P<to>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?))?$'
//	  - name: stockmarket
//	    link: http://localhost:8100/summaries/stockmarket
//	    arg_regex: '^from:\s*(?P<from>\d{4}-\d{2}-\d{2})(?:\s*,\s*to:\s*(?P<to>\d{4}-\d{2}-\d{2}))?$'
//
// Incoming messages must be JSON: {"command":"<name>","body":"<args>"}
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/automations/responder"
	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
)

const defaultInterval = 5 * time.Second

func main() {
	var (
		configPath = flag.String("config", "", "path to endpoints.yaml (default: ~/.pilot/endpoints.yaml)")
		interval   = flag.Duration("interval", defaultInterval, "inbox polling interval (e.g. 5s, 10s, 1m)")
		socket     = flag.String("socket", driver.DefaultSocketPath, "pilot daemon socket path")
	)
	flag.Parse()

	// Load and validate endpoints config.
	// The responder cannot start without a valid endpoints.yaml — fail fast.
	var (
		cfg *responder.Config
		err error
	)
	if *configPath != "" {
		cfg, err = responder.LoadConfigFrom(*configPath)
	} else {
		cfg, err = responder.LoadConfig()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	log.Printf("responder started — %d command(s) loaded, polling every %v", len(cfg.Commands), *interval)
	for _, cmd := range cfg.Commands {
		if cmd.ArgRegex != "" {
			log.Printf("  command %-20s → %s  (regex: %s)", cmd.Name, cmd.Link, cmd.ArgRegex)
		} else {
			log.Printf("  command %-20s → %s", cmd.Name, cmd.Link)
		}
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for range ticker.C {
		if err := processInbox(cfg, *socket); err != nil {
			log.Printf("error: %v", err)
		}
	}
}

// processInbox reads all pending inbox messages and handles each one.
func processInbox(cfg *responder.Config, socketPath string) error {
	messages, err := responder.ReadInbox()
	if err != nil {
		return fmt.Errorf("read inbox: %w", err)
	}
	for _, msg := range messages {
		handleMessage(cfg, socketPath, msg)
	}
	return nil
}

// handleMessage implements the full request–dispatch–reply cycle for one inbox message:
//
//  1. Parse JSON body into {command, body}.
//  2. Validate command and body against endpoints config.
//  3. Call the backing HTTP service.
//  4. Send the service response (or error text) back to the originating node.
//  5. Delete the processed message from the inbox.
func handleMessage(cfg *responder.Config, socketPath string, msg *responder.InboxMessage) {
	req, err := msg.ParseRequest()
	if err != nil {
		log.Printf("[%s] skip unparseable message: %v", msg.From, err)
		_ = msg.Delete()
		return
	}

	log.Printf("[%s] received  command=%q body=%q", msg.From, req.Command, req.Body)

	response, dispatchErr := responder.Dispatch(cfg, req)
	if dispatchErr != nil {
		log.Printf("[%s] dispatch error: %v", msg.From, dispatchErr)
		response = dispatchErr.Error()
	}

	if err := responder.SendReply(socketPath, msg.From, response); err != nil {
		log.Printf("[%s] failed to send reply: %v — will retry next cycle", msg.From, err)
		return
	}

	log.Printf("[%s] replied    %d byte(s)", msg.From, len(response))

	if err := msg.Delete(); err != nil {
		log.Printf("[%s] warning: could not delete inbox message: %v", msg.From, err)
	}
}
