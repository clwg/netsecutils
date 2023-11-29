

## DNS Mapping Process

The DNS forwarding path mapping process consists of the following steps:

1. Set up an authoritative DNS server and configure a domain you control to point to this server. Ensure that the server logs activity and can respond to wildcard queries. For further details, see [dnsauthsink](https://github.com/clwg/netsecutils/tree/main/cmd/dnsauthsink).
2. Generate a subdomain based on the IP address of the target. For example, use formats like `1.2.3.4.example.com` or `alpha.bravo.charlie.delta.example.com`. Refer to [ipencoder](https://github.com/clwg/netsecutils/tree/main/cmd/ipencoder) for more information.
3. Scan a range of IP addresses, using the corresponding encoded domain name for each query.
4. Capture the queries on the authoritative server, noting both the source IP address and the decoded IP address from the subdomain. See [ipdecoder](https://github.com/clwg/netsecutils/tree/main/cmd/ipdecoder) for decoding methods.
5. The combination of the source IP address and the decoded IP address reveals the initial and final hops of the recursive forwarding path taken by the DNS query.