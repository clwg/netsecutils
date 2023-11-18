package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HostResult struct {
	Host   string       `json:"host"`
	Ports  []int        `json:"ports"`
	Banner []BannerInfo `json:"banner"`
}

type BannerInfo struct {
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

func main() {
	var ipRange, portRange string
	flag.StringVar(&ipRange, "iprange", "", "IP range to scan (e.g., 192.168.0.1 or 192.168.0.1-192.168.1.24)")
	flag.StringVar(&portRange, "ports", "", "Port range to scan (e.g., 80-100)")
	flag.Parse()

	ips := strings.Split(ipRange, "-")

	var startIP, endIP net.IP

	// Handle single IP or range of IPs
	switch len(ips) {
	case 1:
		startIP = net.ParseIP(ips[0])
		if startIP == nil {
			fmt.Println("Invalid IP address format")
			return
		}
		// Set endIP to be the same as startIP for single IP
		endIP = startIP
	case 2:
		startIP = net.ParseIP(ips[0])
		endIP = net.ParseIP(ips[1])
		if startIP == nil || endIP == nil {
			fmt.Println("Invalid IP address format")
			return
		}
	default:
		fmt.Println("Invalid IP range format. Use format like 192.168.0.1 or 192.168.0.1-192.168.1.24")
		return
	}

	ports := strings.Split(portRange, "-")
	if len(ports) != 2 {
		fmt.Println("Invalid port range format. Use format like 80-100")
		return
	}

	startPort, endPort, err := parsePortRange(ports[0], ports[1])
	if err != nil {
		fmt.Printf("Invalid port range: %v\n", err)
		return
	}

	// Perform scanning using goroutines
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 1000) // Limit concurrent goroutines
	openPorts := make(map[string][]int)    // Map to store open ports for each host
	var openPortsMutex sync.Mutex          // Mutex to protect the map

	lastIP := false

	for ip := startIP; ; incrementIP(ip) {
		fmt.Printf("scanning: %s\n", ip.String())
		if ip.Equal(endIP) {
			lastIP = true
		}

		for port := startPort; port <= endPort; port++ {
			wg.Add(1)
			semaphore <- struct{}{}
			go func(host string, port int) {
				defer wg.Done()
				if scanHostPort(host, port) {
					openPortsMutex.Lock()
					openPorts[host] = append(openPorts[host], port)
					openPortsMutex.Unlock()
				}
				<-semaphore
			}(ip.String(), port)
		}

		if lastIP {
			break
		}
	}
	wg.Wait()

	for host, ports := range openPorts {
		for _, port := range ports {
			banner, err := grabBanner(host, port)
			if err != nil {
				fmt.Printf("Error grabbing banner for %s:%d: %v\n", host, port, err)
			} else {
				fmt.Printf("Banner for %s:%d: %s\n", host, port, banner)
			}
		}
	}

	var results []HostResult

	for host, ports := range openPorts {
		var banners []BannerInfo
		for _, port := range ports {
			banner, err := grabBanner(host, port)
			if err != nil {
				banners = append(banners, BannerInfo{
					Port:   port,
					Banner: fmt.Sprintf("Error grabbing banner: %v", err),
				})
			} else {
				banners = append(banners, BannerInfo{
					Port:   port,
					Banner: banner,
				})
			}
		}
		results = append(results, HostResult{
			Host:   host,
			Ports:  ports,
			Banner: banners,
		})
	}

	// Serialize the results to JSON
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error serializing results: %v\n", err)
		return
	}

	// Print the JSON serialized data
	fmt.Println(string(jsonData))
}

func scanHostPort(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	fmt.Printf("Open port found: %s:%d\n", host, port) // Print details of open port
	return true
}

func parsePortRange(start, end string) (int, int, error) {
	startPort, err := strconv.Atoi(start)
	if err != nil {
		return 0, 0, err
	}
	endPort, err := strconv.Atoi(end)
	if err != nil {
		return 0, 0, err
	}
	if startPort < 0 || endPort < 0 || startPort > endPort {
		return 0, 0, fmt.Errorf("invalid port range")
	}
	return startPort, endPort, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func grabBanner(host string, port int) (string, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	// First, attempt to connect as if it's an HTTP server
	serverVersion, err := attemptHTTPConnection(address)
	if err == nil {
		return serverVersion, nil
	}

	// If HTTP connection fails, fall back to generic TCP banner grabbing
	return grabTCPPBanner(address)
}

func attemptHTTPConnection(address string) (string, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Send a basic HTTP GET request
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", address)

	// Set a deadline for reading the response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		response := scanner.Text()

		// If the response is an HTTP response, look for the Server header
		if strings.HasPrefix(response, "HTTP/") {
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "Server:") {
					return strings.TrimSpace(strings.TrimPrefix(line, "Server:")), nil
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("no HTTP server detected")
}

func grabTCPPBanner(address string) (string, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Set a deadline for reading the response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
		return scanner.Text(), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("no banner received")
}
