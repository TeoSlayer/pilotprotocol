package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func main() {
	socketPath := flag.String("socket", "/tmp/pilot.sock", "daemon socket path")
	target := flag.String("target", "", "target address (e.g. 0:0000.0000.0002:80)")
	message := flag.String("msg", "hello from pilot client", "message to send")
	flag.Parse()

	if *target == "" {
		log.Fatal("--target required (e.g. 0:0000.0000.0002:80)")
	}

	sa, err := protocol.ParseSocketAddr(*target)
	if err != nil {
		log.Fatalf("parse target: %v", err)
	}

	d, err := driver.Connect(*socketPath)
	if err != nil {
		log.Fatalf("connect to daemon: %v", err)
	}
	defer d.Close()

	log.Printf("dialing %s ...", *target)

	conn, err := d.DialAddr(sa.Addr, sa.Port)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	log.Printf("connected!")

	// Send message
	if _, err := conn.Write([]byte(*message)); err != nil {
		log.Fatalf("write: %v", err)
	}
	log.Printf("sent: %s", *message)

	// Read response
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("read: %v", err)
	}

	fmt.Println(string(buf[:n]))
}
