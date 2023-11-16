package main

import (
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
	"log"
	"os"
)

// XML structs remain the same
type Nmaprun struct {
	Hosts []Host `xml:"host"`
}

type Host struct {
	Addresses []Address `xml:"address"`
	Ports     Ports     `xml:"ports"`
}

type Address struct {
	AddrType string `xml:"addrtype,attr"`
	Addr     string `xml:"addr,attr"`
}

type Ports struct {
	Port []Port `xml:"port"`
}

type Port struct {
	Protocol string  `xml:"protocol,attr"`
	Portid   string  `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}

type State struct {
	State string `xml:"state,attr"`
}

type Service struct {
	Name       string   `xml:"name,attr"`
	Product    string   `xml:"product,attr"`
	Version    string   `xml:"version,attr"`
	Extrainfo  string   `xml:"extrainfo,attr"`
	Ostype     string   `xml:"ostype,attr"`
	Confidence string   `xml:"conf,attr"`
	CPEs       []string `xml:"cpe"`
}

// JSON struct for output
type HostSummary struct {
	Address string     `json:"address"`
	Ports   []PortInfo `json:"ports"`
}

type PortInfo struct {
	Protocol   string   `json:"protocol"`
	Portid     string   `json:"portid"`
	Service    string   `json:"service"`
	Product    string   `json:"product"`
	Version    string   `json:"version"`
	Extrainfo  string   `json:"extrainfo"`
	Ostype     string   `json:"ostype"`
	Confidence string   `json:"confidence"`
	CPEs       []string `json:"cpes"`
}

func main() {
	// Read XML file
	xmlFile, err := os.Open("nmap.xml")
	if err != nil {
		log.Fatal(err)
	}
	defer xmlFile.Close()

	bytes, _ := ioutil.ReadAll(xmlFile)

	var nmaprun Nmaprun
	xml.Unmarshal(bytes, &nmaprun)

	// Convert to JSON structure
	var summaries []HostSummary
	for _, host := range nmaprun.Hosts {
		summary := HostSummary{
			Address: host.Addresses[0].Addr, // Assuming the first address is the primary one
		}

		for _, port := range host.Ports.Port {
			// Check if the port state is "open"
			if port.State.State == "open" {
				portInfo := PortInfo{
					Protocol:   port.Protocol,
					Portid:     port.Portid,
					Service:    port.Service.Name,
					Product:    port.Service.Product,
					Version:    port.Service.Version,
					Extrainfo:  port.Service.Extrainfo,
					Ostype:     port.Service.Ostype,
					Confidence: port.Service.Confidence,
					CPEs:       port.Service.CPEs,
				}
				summary.Ports = append(summary.Ports, portInfo)
			}
		}

		if len(summary.Ports) > 0 {
			summaries = append(summaries, summary)
		}
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(summaries)
	if err != nil {
		log.Fatal(err)
	}

	// Output JSON
	os.Stdout.Write(jsonData)
}
