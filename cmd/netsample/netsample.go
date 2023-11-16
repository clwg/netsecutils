package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	jsonllogger "github.com/clwg/netsecutils/logging"
	packetprocessing "github.com/clwg/netsecutils/packets"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

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

	processor := packetprocessing.NewService(jsonLogger)
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
