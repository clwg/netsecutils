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

	// ... and so on for each type of record

	// Serialize to JSON
	jsonBytes, err := json.MarshalIndent(records, "", "    ")
	if err != nil {
		fmt.Println("Error serializing to JSON:", err)
		return
	}

	fmt.Println(string(jsonBytes))
}
