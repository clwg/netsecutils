package dnsrecord

import (
	"github.com/clwg/netsecutils/pkg/dnsquery"
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

func GetSOARecords(domain string) []SOARecord {
	rawRecords := dnsquery.GetDNSRecords(domain, dns.TypeSOA)
	var soaRecords []SOARecord
	for _, rr := range rawRecords {
		soaRecord := parseSOARecord(rr)
		if soaRecord != nil {
			soaRecords = append(soaRecords, *soaRecord)
		}
	}
	return soaRecords
}

func parseSOARecord(rr dns.RR) *SOARecord {
	soa, ok := rr.(*dns.SOA)
	if !ok {
		return nil
	}
	return &SOARecord{
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
