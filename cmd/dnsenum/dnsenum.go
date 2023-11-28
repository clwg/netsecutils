package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

type SOARecord struct {
	Name       string
	Mbox       string
	Nameserver string
	Serial     uint32
	Refresh    uint32
	Retry      uint32
	Expire     uint32
	Minimum    uint32
}

type MXRecord struct {
	Host string
	Pref uint16
}

type ARecord struct {
	IP   string `json:"ip"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"ttl"`
}

type CNAMERecord struct {
	QueryName string `json:"query_name"`
	Alias     string `json:"alias"`
}

type NSRecord struct {
	Nameserver string
}

type DNSRecords struct {
	SOA   []SOARecord   `json:"soa"`
	MX    []MXRecord    `json:"mx"`
	NS    []NSRecord    `json:"ns"`
	A     []ARecord     `json:"a"`
	SPF   []string      `json:"spf"`
	TXT   []string      `json:"txt"`
	SRV   []string      `json:"srv"`
	CNAME []CNAMERecord `json:"cname"`
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter domain name: ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	records := DNSRecords{}

	// Populate the struct with DNS records
	records.SOA = getSOARecords(domain)
	records.MX = getMXRecords(domain)
	records.NS = getNSRecords(domain)

	aRecords, cnameRecords := getARecords(domain)
	records.A = aRecords
	records.CNAME = cnameRecords

	// ... and so on for each type of record

	// Serialize to JSON
	jsonBytes, err := json.MarshalIndent(records, "", "    ")
	if err != nil {
		fmt.Println("Error serializing to JSON:", err)
		return
	}

	fmt.Println(string(jsonBytes))
}

func getDNSRecords(domain string, qtype uint16) []dns.RR {
	var records []dns.RR
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)

	in, err := dns.Exchange(m, "1.1.1.1:53")
	if err != nil {
		fmt.Printf("Error querying DNS: %s\n", err)
		return records
	}

	records = append(records, in.Answer...)

	return records
}

func getSOARecords(domain string) []SOARecord {
	rawRecords := getDNSRecords(domain, dns.TypeSOA)
	var soaRecords []SOARecord
	for _, rr := range rawRecords {
		soaRecords = append(soaRecords, parseSOARecord(rr))
	}
	return soaRecords
}

func parseSOARecord(rr dns.RR) SOARecord {
	soa, ok := rr.(*dns.SOA)
	if !ok {
		return SOARecord{}
	}
	return SOARecord{
		Name:       soa.Hdr.Name,
		Mbox:       soa.Mbox,
		Nameserver: soa.Ns,
		Serial:     soa.Serial,
		Refresh:    soa.Refresh,
		Retry:      soa.Retry,
		Expire:     soa.Expire,
		Minimum:    soa.Minttl,
	}
}

func getMXRecords(domain string) []MXRecord {
	rawRecords := getDNSRecords(domain, dns.TypeMX)
	var mxRecords []MXRecord
	for _, rr := range rawRecords {
		mxRecords = append(mxRecords, parseMXRecord(rr))
	}
	return mxRecords
}

func parseMXRecord(rr dns.RR) MXRecord {
	mx, ok := rr.(*dns.MX)
	if !ok {
		return MXRecord{}
	}
	return MXRecord{
		Host: mx.Mx,
		Pref: mx.Preference,
	}
}

func getARecords(domain string) ([]ARecord, []CNAMERecord) {
	rawRecords := getDNSRecords(domain, dns.TypeA)
	var aRecords []ARecord
	var cnameRecords []CNAMERecord

	for _, rr := range rawRecords {
		switch rr := rr.(type) {
		case *dns.CNAME:
			cnameRecords = append(cnameRecords, parseCNAMERecord(rr))
		case *dns.A:
			aRecords = append(aRecords, parseARecord(rr))
		}
	}

	return aRecords, cnameRecords
}

func parseCNAMERecord(rr *dns.CNAME) CNAMERecord {
	return CNAMERecord{
		QueryName: rr.Hdr.Name,
		Alias:     rr.Target,
	}
}

func parseARecord(rr dns.RR) ARecord {
	a, ok := rr.(*dns.A)
	if !ok {
		return ARecord{}
	}
	return ARecord{
		IP:   a.A.String(),
		Type: a.Hdr.Rrtype,
		TTL:  a.Hdr.Ttl,
	}
}

func getNSRecords(domain string) []NSRecord {
	rawRecords := getDNSRecords(domain, dns.TypeNS)
	var nsRecords []NSRecord
	for _, rr := range rawRecords {
		nsRecords = append(nsRecords, parseNSRecord(rr))
	}
	return nsRecords
}

func parseNSRecord(rr dns.RR) NSRecord {
	ns, ok := rr.(*dns.NS)
	if !ok {
		return NSRecord{}
	}
	return NSRecord{
		Nameserver: ns.Ns,
	}
}
