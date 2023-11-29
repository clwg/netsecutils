package ipcipher

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
)

// BuildDictionary reads a newline-separated file and returns a slice of strings as the dictionary.
func BuildDictionary(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	dictionary := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		dictionary = append(dictionary, scanner.Text())
	}

	if len(dictionary) < 256 {
		return nil, fmt.Errorf("dictionary should have at least 256 words")
	}

	return dictionary, scanner.Err()
}

// EncodeIPAddress encodes an IP address using a substitution cipher with a given dictionary of words
func EncodeIPAddress(ip net.IP, dictionary []string) string {
	if len(dictionary) < 256 {
		fmt.Println("Error: Dictionary should have at least 256 words.")
		return ""
	}

	octets := ip.To4()
	encoded := make([]string, 4)
	for i, octet := range octets {
		encoded[i] = dictionary[octet]
	}

	return strings.Join(encoded, "-")
}

// DecodeIPAddress decodes an IP address encoded with a substitution cipher using a given dictionary of words.
func DecodeIPAddress(encoded string, dictionary []string) (net.IP, error) {
	encodedOctets := strings.Split(encoded, "-")
	if len(encodedOctets) != 4 {
		return nil, fmt.Errorf("invalid encoded ip address format")
	}

	decoded := make(net.IP, 4)
	for i, encodedOctet := range encodedOctets {
		index := IndexOf(dictionary, encodedOctet)
		if index == -1 {
			return nil, fmt.Errorf("encoded word not found in dictionary")
		}
		decoded[i] = byte(index)
	}

	return decoded, nil
}

func IndexOf(arr []string, str string) int {
	for i, v := range arr {
		if v == str {
			return i
		}
	}
	return -1
}

func GenerateString() string {
	wordLength := rand.Intn(6) + 5 // Generate words of length between 5 and 10 characters
	var word []byte
	for i := 0; i < wordLength; i++ {
		char := byte(rand.Intn(26) + 97) // Generate a random lowercase letter (ASCII: 97-122)
		word = append(word, char)
	}
	return string(word)
}

func Contains(arr []string, str string) bool {
	for _, v := range arr {
		if v == str {
			return true
		}
	}
	return false
}
