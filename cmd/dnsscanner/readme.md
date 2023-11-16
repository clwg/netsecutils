# dnsscanner

A Go-based application that performs DNS queries for specified domains and network ranges, logging the results into a SQLite database. It is designed for network analysis and monitoring DNS requests and responses.

## Features
- Performs DNS queries for a specified domain.
- Supports querying across a given network range.
- Logs DNS query details including timestamp, IP, domain, query, and answer.
- Utilizes SQLite database for storing query logs.
- Configurable timeout for DNS queries.
- Ability to query multiple domains.

Usage
```sh
go run main.go -domain <domain> -network <network> [-domains <domains>] [-timeout <timeout>] [-db <dbfile>]
```
--help
```sh
--domain: Specify the domain to query.
--network: Define the network range for querying.
--timeout: Set the timeout for DNS queries in seconds (default: 5).
--domains: Provide a comma-separated list of additional domains to query.
--db: Specify the SQLite database file (default: dns.db).
```