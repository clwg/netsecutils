package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/clwg/netsecutils/ipcipher"
)

func main() {
	file, err := os.Create("dictionary.txt")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	dictionary := make([]string, 0, 256)

	for len(dictionary) < 256 {
		word := ipcipher.GenerateString()
		if !ipcipher.Contains(dictionary, word) {
			dictionary = append(dictionary, word)
			writer.WriteString(word + "\n")
		}
	}

	writer.Flush()
	fmt.Println("Generated dictionary.txt")
}
