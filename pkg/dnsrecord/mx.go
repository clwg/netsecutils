package dnsrecord

import (
	"github.com/clwg/netsecutils/pkg/dnsquery"
	"github.com/miekg/dns"
)

type MXRecord struct {
	Host string
	Pref uint16
}

func GetMXRecords(domain string) []MXRecord {
	rawRecords := dnsquery.GetDNSRecords(domain, dns.TypeMX)
	var mxRecords []MXRecord
	for _, rr := range rawRecords {
		mx, ok := rr.(*dns.MX)
		if ok {
			mxRecords = append(mxRecords, MXRecord{Host: mx.Mx, Pref: mx.Preference})
		}
	}
	return mxRecords
}
