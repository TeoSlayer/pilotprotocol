package main

import (
	"flag"
	"fmt"
	"log"

	"web4/pkg/driver"
	"web4/pkg/eventstream"
	"web4/pkg/protocol"
)

func main() {
	socketPath := flag.String("socket", "/tmp/pilot.sock", "daemon socket path")
	mode := flag.String("mode", "server", "server, pub, or sub")
	target := flag.String("target", "", "broker address for pub/sub mode")
	topic := flag.String("topic", "*", "topic to subscribe/publish to")
	msg := flag.String("msg", "", "message to publish")
	flag.Parse()

	d, err := driver.Connect(*socketPath)
	if err != nil {
		log.Fatalf("connect to daemon: %v", err)
	}
	defer d.Close()

	switch *mode {
	case "server":
		srv := eventstream.NewServer(d)
		log.Fatal(srv.ListenAndServe())

	case "sub":
		if *target == "" {
			log.Fatal("--target required")
		}
		addr, err := protocol.ParseAddr(*target)
		if err != nil {
			log.Fatalf("parse address: %v", err)
		}
		c, err := eventstream.Subscribe(d, addr, *topic)
		if err != nil {
			log.Fatalf("subscribe: %v", err)
		}
		defer c.Close()
		log.Printf("subscribed to %q on %s", *topic, addr)
		for {
			evt, err := c.Recv()
			if err != nil {
				log.Fatalf("recv: %v", err)
			}
			fmt.Printf("[%s] %s\n", evt.Topic, string(evt.Payload))
		}

	case "pub":
		if *target == "" || *msg == "" {
			log.Fatal("--target and --msg required")
		}
		addr, err := protocol.ParseAddr(*target)
		if err != nil {
			log.Fatalf("parse address: %v", err)
		}
		c, err := eventstream.Subscribe(d, addr, *topic)
		if err != nil {
			log.Fatalf("connect: %v", err)
		}
		defer c.Close()
		if err := c.Publish(*topic, []byte(*msg)); err != nil {
			log.Fatalf("publish: %v", err)
		}
		log.Printf("published to %q: %s", *topic, *msg)

	default:
		log.Fatalf("unknown mode: %s (use server, pub, or sub)", *mode)
	}
}
