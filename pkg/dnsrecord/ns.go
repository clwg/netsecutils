package dnsrecord

import (
	"github.com/clwg/netsecutils/pkg/dnsquery"
	"github.com/miekg/dns"
)

type NSRecord struct {
	Nameserver string `json:"nameserver"`
	Domain     string `json:"domain"`
}

func GetNSRecords(domain string) []NSRecord {
	rawRecords := dnsquery.GetDNSRecords(domain, dns.TypeNS)
	var nsRecords []NSRecord
	for _, rr := range rawRecords {
		ns, ok := rr.(*dns.NS)
		if ok {
			nsRecords = append(nsRecords, NSRecord{Nameserver: ns.Ns, Domain: domain + "."})
		}
	}
	return nsRecords
}
