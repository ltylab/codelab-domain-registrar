package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

const DEFAULT_DATABASE_FILE = "database.yaml"
const DNS_QUERY_TIMEOUT_SECONDS = 10

type RRSet struct {
	Host   string   `yaml:"host"`
	Type   string   `yaml:"type"`
	Ttl    uint16   `yaml:"ttl"`
	Values []string `yaml:"values"`
}

type ZoneMap map[string][]RRSet

type Database struct {
	Zones ZoneMap `yaml:"zone"`
}

type Record struct {
	ZoneName string
	Host     string
	Type     string
	Ttl      uint16
	Value    string
}

type Zone struct {
	Name   string
	RRSets []RRSet
}

func LoadDatabase() ZoneMap {
	dbContent, err := os.ReadFile(dbFile)
	if err != nil {
		log.Printf("Error loading database: %v", err)
	}

	var db Database
	err = yaml.Unmarshal(dbContent, &db)
	if err != nil {
		log.Printf("Error parsing database: %v", err)
	}
	return db.Zones
}

func GetSearchingZoneNames(domain string) (zoneNames []string) {
	zoneNames = []string{}
	slices := strings.Split(domain, ".")
	for i := range slices {
		zoneNames = append(zoneNames, strings.Join(slices[i:], "."))
	}
	return
}

func (zoneMap ZoneMap) FindZone(domain string) *Zone {
	for _, zoneName := range GetSearchingZoneNames(domain) {
		rrSets, ok := zoneMap[zoneName]
		if ok {
			return &Zone{Name: zoneName, RRSets: rrSets}
		}
	}
	return nil
}

func (zone Zone) FindZoneRecords(domain string, recordType uint16) (records []Record) {
	host := strings.TrimRight(domain[:len(domain)-len(zone.Name)], ".")
	recordTypeName := dns.Type(recordType).String()
	records = []Record{}

	for _, rrSet := range zone.RRSets {
		if rrSet.Host != host {
			continue
		}

		if (rrSet.Type == recordTypeName) || (recordType == dns.TypeANY) || (rrSet.Type == "CNAME") {
			for _, value := range rrSet.Values {
				records = append(records, Record{ZoneName: zone.Name, Host: host, Type: rrSet.Type, Ttl: rrSet.Ttl, Value: value})
			}
		}

		if rrSet.Type == "ANAME" && (recordType == dns.TypeANY || recordType == dns.TypeA || recordType == dns.TypeAAAA) {
			records = append(records, ResolveANAME(zone, rrSet)...)
		}
	}
	return
}

type DNSResolveResult struct {
	Addr net.IP
	Type uint16
}

func ResolveHost(fqdn string, requestRecordType uint16) (result []DNSResolveResult, err error) {
	result = []DNSResolveResult{}
	err = nil
	request := new(dns.Msg)
	request.Id = dns.Id()
	request.RecursionDesired = true
	request.Question = make([]dns.Question, 1)
	request.Question[0] = dns.Question{Name: fqdn, Qtype: requestRecordType, Qclass: dns.ClassINET}
	client := new(dns.Client)
	client.Dialer = &net.Dialer{
		Timeout: DNS_QUERY_TIMEOUT_SECONDS * time.Second,
	}
	response, _, err := client.Exchange(request, upstreamServer)
	if err != nil {
		return
	}
	for _, answers := range response.Answer {
		if answers.Header().Rrtype == dns.TypeA {
			result = append(result, DNSResolveResult{Addr: answers.(*dns.A).A, Type: dns.TypeA})
			continue
		}
		if answers.Header().Rrtype == dns.TypeAAAA {
			result = append(result, DNSResolveResult{Addr: answers.(*dns.AAAA).AAAA, Type: dns.TypeAAAA})
			continue
		}
	}
	return
}

func ResolveANAME(zone Zone, rrSet RRSet) (records []Record) {
	records = []Record{}
	for _, value := range rrSet.Values {
		fqdn := value
		if !strings.HasSuffix(fqdn, ".") {
			fqdn = fmt.Sprintf("%s.%s.", fqdn, zone.Name)
		}

		for _, requestRecordType := range []uint16{dns.TypeA, dns.TypeAAAA} {
			resolveResult, err := ResolveHost(fqdn, requestRecordType)
			if err != nil {
				log.Printf("Error looking up ANAME of FQDN %s: %v", fqdn, err)
				continue
			}
			for _, result := range resolveResult {
				responseRecordTypeText, addr := dns.Type(result.Type).String(), result.Addr.String()
				log.Printf("Resolving ANAME of FQDN %s: %s %s", fqdn, responseRecordTypeText, addr)
				records = append(records, Record{
					ZoneName: zone.Name, Host: rrSet.Host, Ttl: rrSet.Ttl,
					Type: responseRecordTypeText, Value: addr,
				})
			}
		}
	}
	return
}

func UpdateSOASerialNumber(rr dns.RR) dns.RR {
	var soa = rr.(*dns.SOA)
	modifiedTime := time.Now().UTC()
	fileInfo, err := os.Stat(dbFile)
	if err != nil {
		log.Printf("Error stat database: %v", err)
	} else {
		modifiedTime = fileInfo.ModTime().UTC()
	}
	soa.Serial = uint32(modifiedTime.Unix())
	log.Printf("Auto updating SOA serial: %s serial = %d", soa.Header().Name, soa.Serial)
	return soa
}

func (record Record) CreateRR() dns.RR {
	host := record.Host
	ttl := record.Ttl
	if host == "" {
		host = "@"
	}
	if ttl <= 0 {
		ttl = 60
	}

	// format: "@ 300 IN CNAME example.com"
	rr, err := dns.NewRR(fmt.Sprintf("$ORIGIN %s\n%s %d IN %s %s", record.ZoneName, host, ttl, record.Type, record.Value))
	if err != nil {
		log.Printf("Failed to create %s record: %v", record.Type, err)
		return nil
	}

	if rr.Header().Rrtype == dns.TypeSOA {
		rr = UpdateSOASerialNumber(rr)
	}

	return rr
}

func GetZoneRRSet(domain string, recordType uint16) (rrSet []dns.RR, rcode int) {
	rrSet = []dns.RR{}
	db := LoadDatabase()
	if db == nil {
		rcode = dns.RcodeServerFailure
		return
	}

	zone := db.FindZone(domain)
	if zone == nil {
		rcode = dns.RcodeNameError
		return
	}

	for _, record := range zone.FindZoneRecords(domain, recordType) {
		rr := record.CreateRR()
		if rr != nil {
			log.Printf("Zone RR for query %s: %v", dns.Type(recordType).String(), rr)
			rrSet = append(rrSet, rr)
		}
	}
	return
}
