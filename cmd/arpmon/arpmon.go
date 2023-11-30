package main

import (
	"flag"
	"log"
	"net"
	"time"

	jsonllogger "github.com/clwg/netsecutils/pkg/logging"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ARPPacket represents the relevant fields of an ARP packet
type ARPPacket struct {
	SourceHWAddr string
	DestHWAddr   string
	SourceIP     net.IP
	DestIP       net.IP
	Operation    uint16 // ARP operation as a numeric code
}

// AppConfig holds configuration data for the ARP monitoring application.
type AppConfig struct {
	LoggerConfig jsonllogger.LoggerConfig
	Device       string
	Snaplen      int
	Promisc      bool
	Timeout      int
}

func main() {
	appConfig := parseFlags()

	jsonLogger, err := jsonllogger.NewLogger(appConfig.LoggerConfig)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	packetSource, handle, err := setupPacketCapture(appConfig)
	if err != nil {
		log.Fatalf("Failed to setup packet capture: %v", err)
	}
	defer handle.Close()

	processPackets(packetSource, jsonLogger)
}

// parseFlags parses command-line flags into an AppConfig.
func parseFlags() AppConfig {
	var config AppConfig
	var rotationTimeInMinutes int // Intermediate variable for rotation time

	flag.StringVar(&config.LoggerConfig.FilenamePrefix, "filenamePrefix", "armon", "Prefix for log filenames")
	flag.StringVar(&config.LoggerConfig.LogDir, "logDir", "./logs", "Directory for log files")
	flag.IntVar(&config.LoggerConfig.MaxLines, "maxLines", 50000, "Maximum number of lines per log file")
	flag.IntVar(&rotationTimeInMinutes, "rotationTime", 30, "Log rotation time in minutes") // Use the intermediate variable here

	flag.StringVar(&config.Device, "device", "enp0s31f6", "Network device for packet capture")
	flag.IntVar(&config.Snaplen, "snaplen", 1600, "Snapshot length for packet capture")
	flag.BoolVar(&config.Promisc, "promisc", true, "Set the interface in promiscuous mode")
	flag.IntVar(&config.Timeout, "timeout", -1, "Timeout for packet capture in seconds")

	flag.Parse()

	config.LoggerConfig.RotationTime = time.Duration(rotationTimeInMinutes) * time.Minute // Convert to time.Duration

	return config
}

// setupPacketCapture initializes and returns a new packet capture source.
func setupPacketCapture(config AppConfig) (*gopacket.PacketSource, *pcap.Handle, error) {
	handle, err := pcap.OpenLive(config.Device, int32(config.Snaplen), config.Promisc, time.Duration(config.Timeout)*time.Second)
	if err != nil {
		return nil, nil, err
	}

	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return packetSource, handle, nil
}

// processPackets processes packets from the given source and logs ARP packets.
func processPackets(packetSource *gopacket.PacketSource, jsonLogger *jsonllogger.Logger) {
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			arpPacket := ARPPacket{
				SourceHWAddr: net.HardwareAddr(arp.SourceHwAddress).String(),
				DestHWAddr:   net.HardwareAddr(arp.DstHwAddress).String(),
				SourceIP:     net.IP(arp.SourceProtAddress),
				DestIP:       net.IP(arp.DstProtAddress),
				Operation:    arp.Operation,
			}
			jsonLogger.Log(arpPacket)
		}
	}
}
