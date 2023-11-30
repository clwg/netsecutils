package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/clwg/netsecutils/pkg/dnsrecord"
)

func main() {
	domainPtr := flag.String("domain", "", "Domain name")
	srvPtr := flag.Bool("srv", false, "Enable SRV record enumeration")
	flag.Parse()

	if *domainPtr == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter domain name: ")
		domain, _ := reader.ReadString('\n')
		*domainPtr = strings.TrimSpace(domain)
	}

	records := dnsrecord.DNSRecords{}

	// Iterate domain hierarchy to find SOA record
	domainParts := strings.Split(*domainPtr, ".")
	for i := 0; i < len(domainParts); i++ {
		subDomain := strings.Join(domainParts[i:], ".")
		soaRecords := dnsrecord.GetSOARecords(subDomain)
		if len(soaRecords) > 0 {
			records.SOA = soaRecords
			break
		}
	}

	zone := records.SOA[0].Name

	records.MX = dnsrecord.GetMXRecords(zone)
	records.NS = dnsrecord.GetNSRecords(zone)
	records.TXT = dnsrecord.GetTXTRecords(zone)

	// A records
	records.A, records.CNAME = dnsrecord.GetARecords(*domainPtr)

	if *srvPtr {
		// srv enum
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
			records.SRV = append(records.SRV, dnsrecord.GetSRVRecords(zone, svc.service, svc.protocol)...)
		}
	}

	// Serialize to JSON
	jsonBytes, err := json.MarshalIndent(records, "", "    ")
	if err != nil {
		fmt.Println("Error serializing to JSON:", err)
		return
	}

	fmt.Println(string(jsonBytes))
}
