package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

type DnsQuery struct {
	Timestamp time.Time `json:"timestamp"`
	Ip        string    `json:"ip"`
	Domain    string    `json:"domain"`
	Query     string    `json:"query"`
	Answer    string    `json:"answer"`
}

func main() {
	domain := flag.String("domain", "", "Domain to query")
	network := flag.String("network", "", "Network range to query")
	timeout := flag.Int("timeout", 5, "Timeout for DNS queries in seconds")
	flag.Parse()

	client := dns.Client{Timeout: time.Duration(*timeout) * time.Second}

	ip, ipnet, err := net.ParseCIDR(*network)
	if err != nil {
		panic(err)
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		combinedDomain := fmt.Sprintf("%s.%s", ip.String(), *domain) // Combining IP and domain
		msg := dns.Msg{}
		msg.SetQuestion(dns.Fqdn(combinedDomain), dns.TypeA)
		resp, _, err := client.Exchange(&msg, net.JoinHostPort(ip.String(), "53"))
		if err != nil {
			fmt.Printf("query request timeout: %s\n", err)
			continue
		}

		query := dnsQuestionToString(msg.Question[0])
		answer := dnsRRToString(resp.Answer)

		dnsQuery := DnsQuery{
			Timestamp: time.Now(),
			Ip:        ip.String(),
			Domain:    combinedDomain,
			Query:     query,
			Answer:    answer,
		}

		jsonData, err := json.Marshal(dnsQuery)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(jsonData))
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func dnsQuestionToString(q dns.Question) string {
	return fmt.Sprintf("%s %s", q.Name, dns.TypeToString[q.Qtype])
}

func dnsRRToString(rr []dns.RR) string {
	var str string
	for _, r := range rr {
		str += r.String() + "\n"
	}
	return str
}
