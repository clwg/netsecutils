package dnsquery

import (
	"fmt"

	"github.com/miekg/dns"
)

func GetDNSRecords(domain string, qtype uint16) []dns.RR {
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
