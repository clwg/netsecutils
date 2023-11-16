package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/clwg/netsecutils/ipcipher"
)

func main() {
	ipFlag := flag.String("ip", "", "IP address to encode and decode")
	dictfile := flag.String("dictionary", "dictionary.txt", "Dictionary file")

	flag.Parse()

	dictionary, err := ipcipher.BuildDictionary(*dictfile)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	ip := net.ParseIP(*ipFlag)
	encoded := ipcipher.EncodeIPAddress(ip, dictionary)
	fmt.Println(encoded)
}
