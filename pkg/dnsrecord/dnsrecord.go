package dnsrecord

type DNSRecords struct {
	SOA   []SOARecord   `json:"soa"`
	MX    []MXRecord    `json:"mx"`
	NS    []NSRecord    `json:"ns"`
	A     []ARecord     `json:"a"`
	SPF   []string      `json:"spf"`
	TXT   []TXTRecord   `json:"txt"`
	SRV   []SRVRecord   `json:"srv"`
	CNAME []CNAMERecord `json:"cname"`
}
