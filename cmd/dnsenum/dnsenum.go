package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/clwg/netsecutils/pkg/dnsrecord"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter domain name: ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	records := dnsrecord.DNSRecords{}

	// Populate the struct with DNS records
	records.SOA = dnsrecord.GetSOARecords(domain)
	records.MX = dnsrecord.GetMXRecords(domain)
	records.NS = dnsrecord.GetNSRecords(domain)
	records.A, records.CNAME = dnsrecord.GetARecords(domain)

	// sip enum
	services := []struct {
		service  string
		protocol string
	}{
		{"sip", "tcp"}, {"sip", "udp"},
		{"sips", "tcp"},
		{"xmpp-server", "tcp"}, {"xmpp-server", "udp"},
		{"xmpp-client", "tcp"}, {"xmpp-client", "udp"},
		{"jabber", "tcp"},
		{"ldap", "tcp"}, {"ldap", "udp"},
		{"http", "tcp"},
		{"https", "tcp"},
		{"ftp", "tcp"},
		{"smtp", "tcp"},
		{"imap", "tcp"},
		{"pop3", "tcp"},
		{"autodiscover", "tcp"},
		{"kerberos", "tcp"}, {"kerberos", "udp"},
		{"msoid", "tcp"},
		{"h323cs", "tcp"},
		{"h323ls", "tcp"},
		{"rtp", "tcp"}, {"rtp", "udp"},
		{"carddav", "tcp"},
		{"caldav", "tcp"},
		{"irc", "tcp"},
		{"ircs", "tcp"},
		{"minecraft", "tcp"},
	}

	// Append SRV records for each service-protocol combination
	for _, svc := range services {
		records.SRV = append(records.SRV, dnsrecord.GetSRVRecords(domain, svc.service, svc.protocol)...)
	}

	// ... and so on for each type of record

	// Serialize to JSON
	jsonBytes, err := json.MarshalIndent(records, "", "    ")
	if err != nil {
		fmt.Println("Error serializing to JSON:", err)
		return
	}

	fmt.Println(string(jsonBytes))
}
