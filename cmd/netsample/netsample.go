package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	jsonllogger "github.com/clwg/netsecutils/logging"
	"github.com/clwg/netsecutils/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/patrickmn/go-cache"
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

// PacketProcessor interface for processing packets
type PacketProcessor interface {
	Process(packet gopacket.Packet)
}

// Logger interface for logging
type Logger interface {
	Log(message string)
}

// ConsoleLogger is a concrete implementation of Logger
type ConsoleLogger struct{}

func (l *ConsoleLogger) Log(message string) {
	fmt.Println(message)
}

func main() {
	// Command-line flags
	interfaceName := flag.String("interface", "", "Network interface to capture packets from")
	pcapFile := flag.String("pcapfile", "", "Path to the pcap file")
	bpfFilter := flag.String("filter", "tcp or udp or icmp", "BPF filter string")
	flag.Parse()

	config := jsonllogger.LoggerConfig{
		FilenamePrefix: "netsample",
		LogDir:         "./logs",
		MaxLines:       50000,
		RotationTime:   30 * time.Minute,
	}

	jsonLogger, err := jsonllogger.NewLogger(config)
	if err != nil {
		panic(err)
	}

	processor := NewService(jsonLogger)
	logger := &ConsoleLogger{}

	if *pcapFile != "" {
		runPacketFileProcessing(*pcapFile, *bpfFilter, processor, logger)
	} else if *interfaceName != "" {
		runPacketCapture(*interfaceName, *bpfFilter, processor, logger)
	} else {
		log.Fatal("Please specify either an interface or a pcap file")
	}

}

func runPacketCapture(interfaceName, bpfFilter string, processor PacketProcessor, logger Logger) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	applyBPFFilter(handle, bpfFilter)
	processPackets(handle, processor)
}

func runPacketFileProcessing(filePath, bpfFilter string, processor PacketProcessor, logger Logger) {
	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	applyBPFFilter(handle, bpfFilter)
	processPackets(handle, processor)
}

func applyBPFFilter(handle *pcap.Handle, bpfFilter string) {
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatal(err)
	}
}

func processPackets(handle *pcap.Handle, processor PacketProcessor) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processor.Process(packet)
	}
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

	}
}
