package dnsrecord

import (
	"fmt"

	"github.com/clwg/netsecutils/pkg/dnsquery"
	"github.com/miekg/dns"
)

// SRVRecord represents a DNS SRV record.
type SRVRecord struct {
	Service  string `json:"service"`
	Proto    string `json:"proto"`
	Name     string `json:"name"`
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	TTL      uint32 `json:"ttl"`
}

// GetSRVRecords queries DNS for SRV records of well-known services for the given domain.
func GetSRVRecords(domain string, service string, proto string) []SRVRecord {
	query := fmt.Sprintf("_%s._%s.%s", service, proto, domain)
	rawRecords := dnsquery.GetDNSRecords(query, dns.TypeSRV)
	var srvRecords []SRVRecord

	for _, rr := range rawRecords {
		if srv, ok := rr.(*dns.SRV); ok {
			srvRecords = append(srvRecords, parseSRVRecord(srv, service, proto))
		}
	}

	return srvRecords
}

// parseSRVRecord converts a dns.SRV record to an SRVRecord struct.
func parseSRVRecord(rr *dns.SRV, service string, proto string) SRVRecord {
	return SRVRecord{
		Service:  service,
		Proto:    proto,
		Name:     rr.Hdr.Name,
		Target:   rr.Target,
		Port:     rr.Port,
		Priority: rr.Priority,
		Weight:   rr.Weight,
		TTL:      rr.Hdr.Ttl,
	}
}
