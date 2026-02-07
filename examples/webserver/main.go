package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"web4/pkg/driver"
)

func main() {
	socketPath := flag.String("socket", "/tmp/pilot.sock", "daemon socket path")
	port := flag.Uint("port", 80, "pilot port to listen on")
	flag.Parse()

	d, err := driver.Connect(*socketPath)
	if err != nil {
		log.Fatalf("connect to daemon: %v", err)
	}
	defer d.Close()

	ln, err := d.Listen(uint16(*port))
	if err != nil {
		log.Fatalf("listen on port %d: %v", *port, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Pilot Protocol</title></head>
<body>
<h1>Hello from Pilot Protocol</h1>
<p>This page is served over the Pilot Protocol overlay network.</p>
<p>You are connected to an agent at address: %s</p>
</body>
</html>`, ln.Addr())
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","protocol":"pilot","port":%d}`, *port)
	})

	log.Printf("webserver listening on pilot port %d", *port)
	log.Fatal(http.Serve(ln, mux))
}
