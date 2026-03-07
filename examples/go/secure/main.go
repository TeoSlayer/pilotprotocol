package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/secure"
)

func main() {
	socketPath := flag.String("socket", "/tmp/pilot.sock", "daemon socket path")
	mode := flag.String("mode", "server", "server or client")
	target := flag.String("target", "", "target address for client mode")
	msg := flag.String("msg", "hello secure channel", "message to send in client mode")
	flag.Parse()

	d, err := driver.Connect(*socketPath)
	if err != nil {
		log.Fatalf("connect to daemon: %v", err)
	}
	defer d.Close()

	switch *mode {
	case "server":
		srv := secure.NewServer(d, func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, 65535)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				log.Printf("received (encrypted): %s", string(buf[:n]))
				reply := fmt.Sprintf("secure-echo: %s", string(buf[:n]))
				conn.Write([]byte(reply))
			}
		})
		log.Fatal(srv.ListenAndServe())

	case "client":
		if *target == "" {
			log.Fatal("--target required")
		}
		addr, err := protocol.ParseAddr(*target)
		if err != nil {
			log.Fatalf("parse address: %v", err)
		}
		sc, err := secure.Dial(d, addr)
		if err != nil {
			log.Fatalf("secure dial: %v", err)
		}
		defer sc.Close()
		log.Printf("secure channel established to %s", addr)

		if _, err := sc.Write([]byte(*msg)); err != nil {
			log.Fatalf("write: %v", err)
		}
		log.Printf("sent: %s", *msg)

		buf := make([]byte, 65535)
		n, err := sc.Read(buf)
		if err != nil {
			log.Fatalf("read: %v", err)
		}
		fmt.Println(string(buf[:n]))

	default:
		log.Fatalf("unknown mode: %s (use server or client)", *mode)
	}
}
