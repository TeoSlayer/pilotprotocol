package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"web4/pkg/dataexchange"
	"web4/pkg/driver"
	"web4/pkg/protocol"
)

func main() {
	socketPath := flag.String("socket", "/tmp/pilot.sock", "daemon socket path")
	mode := flag.String("mode", "server", "server or client")
	target := flag.String("target", "", "target address for client mode (e.g. 0:0000.0000.0007)")
	msg := flag.String("msg", "hello from data exchange", "message to send in client mode")
	flag.Parse()

	d, err := driver.Connect(*socketPath)
	if err != nil {
		log.Fatalf("connect to daemon: %v", err)
	}
	defer d.Close()

	switch *mode {
	case "server":
		runServer(d)
	case "client":
		if *target == "" {
			log.Fatal("--target required in client mode")
		}
		addr, err := protocol.ParseAddr(*target)
		if err != nil {
			log.Fatalf("parse address: %v", err)
		}
		runClient(d, addr, *msg)
	default:
		log.Fatalf("unknown mode: %s (use server or client)", *mode)
	}
}

func runServer(d *driver.Driver) {
	handler := func(conn net.Conn, frame *dataexchange.Frame) {
		log.Printf("received %s frame (%d bytes) from %s",
			dataexchange.TypeName(frame.Type), len(frame.Payload), conn.RemoteAddr())

		switch frame.Type {
		case dataexchange.TypeText:
			log.Printf("  text: %s", string(frame.Payload))
		case dataexchange.TypeJSON:
			log.Printf("  json: %s", string(frame.Payload))
		case dataexchange.TypeFile:
			log.Printf("  file: %s (%d bytes)", frame.Filename, len(frame.Payload))
		case dataexchange.TypeBinary:
			log.Printf("  binary: %d bytes", len(frame.Payload))
		}

		// Echo back an ACK
		ack := &dataexchange.Frame{
			Type:    dataexchange.TypeText,
			Payload: []byte(fmt.Sprintf("ack: received %s (%d bytes)", dataexchange.TypeName(frame.Type), len(frame.Payload))),
		}
		dataexchange.WriteFrame(conn, ack)
	}

	srv := dataexchange.NewServer(d, handler)
	log.Fatal(srv.ListenAndServe())
}

func runClient(d *driver.Driver, addr protocol.Addr, msg string) {
	c, err := dataexchange.Dial(d, addr)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer c.Close()

	log.Printf("connected to %s:1001", addr)

	// Send a text frame
	if err := c.SendText(msg); err != nil {
		log.Fatalf("send text: %v", err)
	}
	log.Printf("sent text: %s", msg)

	// Send a JSON frame
	if err := c.SendJSON([]byte(`{"type":"ping","seq":1}`)); err != nil {
		log.Fatalf("send json: %v", err)
	}
	log.Println("sent json")

	// Read ACKs
	for i := 0; i < 2; i++ {
		frame, err := c.Recv()
		if err != nil {
			log.Fatalf("recv: %v", err)
		}
		log.Printf("response: %s", string(frame.Payload))
	}
}
