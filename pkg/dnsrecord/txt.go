package dnsrecord

import (
	"github.com/clwg/netsecutils/pkg/dnsquery"
	"github.com/miekg/dns"
)

type TXTRecord struct {
	Record string `json:"txt"`
	Domain string `json:"domain"`
}

func GetTXTRecords(domain string) []TXTRecord {
	rawRecords := dnsquery.GetDNSRecords(domain, dns.TypeTXT)
	var txtRecords []TXTRecord
	for _, rr := range rawRecords {
		txt, ok := rr.(*dns.TXT)
		if ok {
			txtRecords = append(txtRecords, TXTRecord{Record: txt.String(), Domain: domain})
		}
	}
	return txtRecords
}
