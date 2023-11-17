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
	maxHops      = 30
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: traceroute [host]")
		os.Exit(1)
	}
	targetHost := os.Args[1]

	if err := traceroute(targetHost); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func traceroute(host string) error {
	dest, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return err
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	defer conn.Close()

	for ttl := 1; ttl <= maxHops; ttl++ {
		err := traceHop(conn, ttl, dest)
		if err != nil {
			fmt.Println("Error:", err)
			break
		}
	}

	return nil
}

func traceHop(conn *icmp.PacketConn, ttl int, dest *net.IPAddr) error {
	// Set the TTL
	if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
		return err
	}

	// Create an ICMP echo request packet
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  ttl,
			Data: []byte(""),
		},
	}
	msgData, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	// Send the packet
	startTime := time.Now()
	_, err = conn.WriteTo(msgData, dest)
	if err != nil {
		return err
	}

	// Listen for a reply
	reply := make([]byte, 1500)
	err = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		return err
	}
	n, peer, err := conn.ReadFrom(reply)
	duration := time.Since(startTime)

	if err != nil {
		fmt.Println("  *")
		return nil
	}

	rm, err := icmp.ParseMessage(protocolICMP, reply[:n])
	if err != nil {
		return err
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		fmt.Printf("%d\t%s\t%v\n", ttl, peer, duration)
		os.Exit(0)
	case ipv4.ICMPTypeTimeExceeded:
		fmt.Printf("%d\t%s\t%v\n", ttl, peer, duration)
	default:
		fmt.Printf("%d\tunknown message: %+v\n", ttl, rm)
	}

	return nil
}
