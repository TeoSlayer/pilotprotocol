package main

import (
	"flag"
	"fmt"
	"io"
	"log"

	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func main() {
	socketPath := flag.String("socket", "/tmp/pilot.sock", "daemon socket path")
	target := flag.String("target", "", "target address (e.g. 0:0000.0000.0002)")
	port := flag.Uint("port", 80, "target port")
	path := flag.String("path", "/status", "HTTP path to request")
	flag.Parse()

	if *target == "" {
		log.Fatal("--target required (e.g. 0:0000.0000.0002)")
	}

	addr, err := protocol.ParseAddr(*target)
	if err != nil {
		log.Fatalf("parse target: %v", err)
	}

	d, err := driver.Connect(*socketPath)
	if err != nil {
		log.Fatalf("connect to daemon: %v", err)
	}
	defer d.Close()

	log.Printf("dialing %s:%d ...", addr, *port)

	conn, err := d.DialAddr(addr, uint16(*port))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	log.Println("connected, sending HTTP request...")

	// Send HTTP/1.0 request
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: pilot\r\nConnection: close\r\n\r\n", *path)
	if _, err := conn.Write([]byte(req)); err != nil {
		log.Fatalf("write: %v", err)
	}

	// Read full response
	resp, err := io.ReadAll(conn)
	if err != nil && err != io.EOF {
		log.Fatalf("read: %v", err)
	}

	fmt.Println(string(resp))
	log.Printf("done (%d bytes received)", len(resp))
}
