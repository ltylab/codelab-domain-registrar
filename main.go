package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"
)

var dbFile string
var isAuthoritativeServer bool
var upstreamServer string

func main() {
	addr := flag.String("port", ":53", "port to run the DNS server on")
	disableTcp := flag.Bool("notcp", false, "disable TCP listen")
	disableUdp := flag.Bool("noudp", false, "disable UDP listen")
	notAuthoritative := flag.Bool("notaut", false, "disable authoritative flag in DNS response")
	db := flag.String("db", DEFAULT_DATABASE_FILE, "path to the database TOML file")
	upstream := flag.String("upstream", "1.1.1.1:53", "path to the database TOML file")
	flag.Parse()

	dbFile = *db
	upstreamServer = *upstream
	isAuthoritativeServer = !*notAuthoritative
	log.Printf("Database path: %s", dbFile)

	var servers []*dns.Server
	if !*disableTcp {
		servers = append(servers, StartDNSServer("tcp", *addr))
	}
	if !*disableUdp {
		servers = append(servers, StartDNSServer("udp", *addr))
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down DNS servers...")
	for _, server := range servers {
		err := server.Shutdown()
		if err != nil {
			log.Printf("Error shutting down UDP server: %v", err)
		}
	}
	log.Println("DNS servers stopped.")
}
