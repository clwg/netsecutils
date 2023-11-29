package main

import (
	"flag"
	"fmt"
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

func main() {
	// Log configuration defaults
	var (
		filenamePrefix = flag.String("filenamePrefix", "netsample", "Prefix for log filenames")
		logDir         = flag.String("logDir", "../../logs/arpmon", "Directory for log files")
		maxLines       = flag.Int("maxLines", 50000, "Maximum number of lines per log file")
		rotationTime   = flag.Int("rotationTime", 30, "Log rotation time in minutes")
	)

	// PCAP configuration defaults
	var (
		device  = flag.String("device", "enp0s31f6", "Network device for packet capture")
		snaplen = flag.Int("snaplen", 1600, "Snapshot length for packet capture")
		promisc = flag.Bool("promisc", true, "Set the interface in promiscuous mode")
		timeout = flag.Int("timeout", -1, "Timeout for packet capture in seconds")
	)

	flag.Parse()

	config := jsonllogger.LoggerConfig{
		FilenamePrefix: *filenamePrefix,
		LogDir:         *logDir,
		MaxLines:       *maxLines,
		RotationTime:   time.Duration(*rotationTime) * time.Minute,
	}

	jsonLogger, err := jsonllogger.NewLogger(config)
	if err != nil {
		panic(err)
	}

	// Open the device for capturing
	handle, err := pcap.OpenLive(*device, int32(*snaplen), *promisc, time.Duration(*timeout)*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set the filter for ARP packets
	if err := handle.SetBPFFilter("arp"); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

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
			fmt.Println(arpPacket)
		}
	}
}
