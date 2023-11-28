package dnsrecord

import (
	"github.com/clwg/netsecutils/pkg/dnsquery"
	"github.com/miekg/dns"
)

type ARecord struct {
	RNAME string `json:"rname"`
	IP    string `json:"ip"`
	Type  uint16 `json:"type"`
	TTL   uint32 `json:"ttl"`
}

type CNAMERecord struct {
	Name  string `json:"name"`
	Alias string `json:"alias"`
}

func GetARecords(domain string) ([]ARecord, []CNAMERecord) {
	rawRecords := dnsquery.GetDNSRecords(domain, dns.TypeA)
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

func parseARecord(rr dns.RR) ARecord {
	a, ok := rr.(*dns.A)
	if !ok {
		return ARecord{}
	}
	return ARecord{
		RNAME: a.Hdr.Name,
		IP:    a.A.String(),
		Type:  a.Hdr.Rrtype,
		TTL:   a.Hdr.Ttl,
	}
}

func parseCNAMERecord(rr *dns.CNAME) CNAMERecord {
	return CNAMERecord{
		Name:  rr.Hdr.Name,
		Alias: rr.Target,
	}
}
