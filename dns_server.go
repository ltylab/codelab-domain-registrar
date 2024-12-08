package main

import (
	"log"
	"strings"

	"github.com/miekg/dns"
)

func DNSHandler(writer dns.ResponseWriter, request *dns.Msg) {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = isAuthoritativeServer

	for _, question := range request.Question {
		log.Printf("DNS query from %s://%s: %s %s %s",
			writer.RemoteAddr().Network(),
			writer.RemoteAddr().String(),
			question.Name,
			dns.Class(question.Qclass).String(),
			dns.Type(question.Qtype).String())
		rr, rcode := GetZoneRRSet(strings.TrimRight(strings.ToLower(question.Name), "."), question.Qtype)
		if rcode != dns.RcodeSuccess {
			log.Printf("Response code %s: %s", writer.RemoteAddr().String(), dns.RcodeToString[rcode])
			response.Rcode = rcode
			break
		}
		response.Answer = append(response.Answer, rr...)
	}

	err := writer.WriteMsg(response)
	if err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func StartDNSServer(network, addr string) *dns.Server {
	server := &dns.Server{Addr: addr, Net: network}
	dns.HandleFunc(".", DNSHandler)

	go func() {
		log.Printf("Starting DNS server on %s/%s", addr, network)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start %s server: %v", network, err)
		}
	}()

	return server
}
