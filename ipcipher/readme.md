# IP Cipher

This package provides functions to encode and decode IP addresses using a substitution cipher with a given dictionary of words.

## Usage

First, build a dictionary by calling BuildDictionary with the filename of a newline-separated file containing at least 256 words. This function returns a slice of strings representing the dictionary.

```go
dictionary, err := BuildDictionary("dictionary.txt")
if err != nil {
    // handle error
}
```

To encode an IP, call EncodeIPAddress with an net.IP value and the dictionary. This function returns a string representing the encoded IP address.

```go
ip := net.ParseIP("127.0.0.1")
encoded := EncodeIPAddress(ip, dictionary)
```

To decode an encoded IP address, call DecodeIPAddress with the encoded string and the dictionary. This function returns a net.IP value representing the decoded IP address.

```go
decodedIP, err := DecodeIPAddress(encoded, dictionary)
if err != nil {
    // handle error
}
```

For a reference implementation refer to ./cmd/ip-word-cipher-example.go 
