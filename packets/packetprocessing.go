package packetprocessing

import (
	"fmt"
	"time"

	"github.com/clwg/netsecutils/utils"
	"github.com/clwg/netsecutils/logging"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/patrickmn/go-cache" // Import the go-cache library
)

// L4Sample struct to hold L4Sample related information
type L4Sample struct {
	Timestamp       time.Time
	SourcePort      uint16
	DestinationPort uint16
}

// PacketData struct to hold packet information
type PacketData struct {
	L4Sample       L4Sample
	UUID           string
	SourceMAC      string
	DestinationMAC string
	SourceIP       string
	DestinationIP  string
	Protocol       string
}

// Service struct for packet processing
type Service struct {
	cache  *cache.Cache        // Adding cache field to the Service struct
	logger *jsonllogger.Logger // Adding logger field to the Service struct

}

// NewService creates a new instance of the packet processing service
func NewService(logger *jsonllogger.Logger) *Service {
	return &Service{
		cache:  cache.New(5*time.Minute, 10*time.Minute), // Initialize cache with a default expiration time and cleanup interval
		logger: logger,
	}
}

func (s *Service) Process(packet gopacket.Packet) {
	data := PacketData{
		L4Sample: L4Sample{
			Timestamp: packet.Metadata().Timestamp,
		},
	}

	// Ethernet layer
	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		data.SourceMAC = ethernetPacket.SrcMAC.String()
		data.DestinationMAC = ethernetPacket.DstMAC.String()
	}

	// IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		data.SourceIP = ipPacket.SrcIP.String()
		data.DestinationIP = ipPacket.DstIP.String()
		data.Protocol = ipPacket.Protocol.String()
	}

	// TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcpPacket, _ := tcpLayer.(*layers.TCP)
		data.L4Sample.SourcePort = uint16(tcpPacket.SrcPort)
		data.L4Sample.DestinationPort = uint16(tcpPacket.DstPort)
	}

	// UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udpPacket, _ := udpLayer.(*layers.UDP)
		data.L4Sample.SourcePort = uint16(udpPacket.SrcPort)
		data.L4Sample.DestinationPort = uint16(udpPacket.DstPort)
	}

	// Generate compound key
	compoundKey := data.SourceMAC + data.SourceIP + data.DestinationMAC + data.DestinationIP + data.Protocol

	// Generate UUID
	uuid, err := utils.GenerateUUIDv5(compoundKey)
	if err != nil {
		fmt.Printf("Error generating UUID: %v\n", err)
		return
	}
	data.UUID = uuid.String()

	// Check if the compound key exists in the cache
	if _, found := s.cache.Get(compoundKey); !found {
		// If not found, add the key to the cache and print the data
		s.cache.Set(compoundKey, nil, cache.DefaultExpiration)
		s.logger.Log(data)

		/*
			jsonData, err := json.Marshal(data)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println(string(jsonData))
		*/

		/*
			fmt.Printf("%v, %s, %s, %s, %d, %s, %s, %d, %s\n",
				data.L4Sample.Timestamp, data.UUID, data.SourceMAC, data.SourceIP, data.L4Sample.SourcePort,
				data.DestinationMAC, data.DestinationIP, data.L4Sample.DestinationPort, data.Protocol)
		*/

	}
}
