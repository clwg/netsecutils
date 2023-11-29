package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/clwg/netsecutils/pkg/ipcipher"
)

func main() {
	domainFlag := flag.String("domain", "", "domain to decode")
	dictfile := flag.String("dictionary", "dictionary.txt", "Dictionary file")

	flag.Parse()

	dictionary, err := ipcipher.BuildDictionary(*dictfile)
	if err != nil {
		log.Fatalf("Error building dictionary: %v\n", err)
	}

	encodedString := strings.Split(*domainFlag, ".")[0]

	decoded, err := ipcipher.DecodeIPAddress(encodedString, dictionary)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println(decoded)
	}
}
