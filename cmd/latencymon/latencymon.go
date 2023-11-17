package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	protocolICMP = 1
)

var (
	latencies       []time.Duration
	totalPings      int
	successfulPings int
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./latencymon <host>")
		os.Exit(1)
	}

	host := os.Args[1]
	destAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		fmt.Println("Error resolving address:", err)
		os.Exit(1)
	}

	listener, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Println("Error listening for ICMP packets:", err)
		os.Exit(1)
	}
	defer listener.Close()

	for {
		sendTime := time.Now()
		totalPings++

		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: os.Getpid() & 0xffff, Seq: totalPings,
				Data: []byte("HELLO-R-U-THERE"),
			},
		}

		wb, err := msg.Marshal(nil)
		if err != nil {
			fmt.Println("Error marshaling message:", err)
			continue
		}

		if _, err := listener.WriteTo(wb, destAddr); err != nil {
			fmt.Println("Error sending ICMP packet:", err)
			continue
		}

		rb := make([]byte, 1500)
		err = listener.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			fmt.Println("Error setting read deadline:", err)
			continue
		}

		n, _, err := listener.ReadFrom(rb)
		if err != nil {
			fmt.Println("Error reading ICMP packet:", err)
			continue
		}

		rm, err := icmp.ParseMessage(protocolICMP, rb[:n])
		if err != nil {
			fmt.Println("Error parsing ICMP message:", err)
			continue
		}

		if rm.Type == ipv4.ICMPTypeEchoReply {
			successfulPings++
			latency := time.Since(sendTime)
			latencies = append(latencies, latency)

			printStats(latency)
		}

		time.Sleep(1 * time.Second)
	}
}

func printStats(latency time.Duration) {
	fmt.Printf("Latency: %v ", latency)

	if len(latencies) > 10 {
		avgLast10 := average(latencies[len(latencies)-10:])
		fmt.Printf("Avg last 10 pings: %v ", avgLast10)
	}

	if len(latencies) > 100 {
		avgLast100 := average(latencies[len(latencies)-100:])
		fmt.Printf("Avg last 100 pings: %v ", avgLast100)
	}

	packetLoss := float64(totalPings-successfulPings) / float64(totalPings) * 100
	fmt.Printf("Packet Loss: %.2f%%\n", packetLoss)

}

func average(durations []time.Duration) time.Duration {
	total := time.Duration(0)
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}
