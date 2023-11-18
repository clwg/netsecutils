# tcpscan

tcpscan is a simple, concurrent TCP port scanner written in Go. It scans a range of IP addresses and ports, and attempts to grab banners from open ports.

## Features

- Concurrent scanning of multiple IP addresses and ports.
- Supports both single IP and range of IPs.
- Supports range of ports.
- Attempts to grab banners from open ports.
- Outputs the scan results in JSON format.

## Usage

You can use the `tcpscan` command with the `-iprange` and `-ports` flags to specify the IP range and port range to scan.

```bash
go run tcpscan.go -iprange 192.168.0.1-192.168.1.24 -ports 80-100
```

The `-iprange` flag accepts either a single IP address or a range of IP addresses. The `-ports` flag accepts a range of ports.

## Output

The output of the scan is a JSON array of objects, each representing a host. Each host object includes the host IP, an array of open ports, and an array of banners grabbed from each open port.

```json
[
  {
    "host": "192.168.0.1",
    "ports": [80, 443],
    "banner": [
      {
        "port": 80,
        "banner": "Apache/2.4.18 (Ubuntu)"
      },
      {
        "port": 443,
        "banner": "Error grabbing banner: ..."
      }
    ]
  },
  ...
]
```

## Dependencies

tcpscan is written in Go and uses only the standard library, so there are no external dependencies.

## License

tcpscan is open-source software released under the MIT License.