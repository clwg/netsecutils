# IP Decoder

This is a simple Go program that decodes an encoded IP address from a given domain.

## Usage

The program accepts two command-line flags:

- `-domain`: The domain to decode. The encoded IP address should be the first part of the domain, before the first dot.
- `-dictionary`: The path to the dictionary file to use for decoding. Defaults to `dictionary.txt`.

## Example

```bash
go run ipdecoder.go -domain encoded.example.com -dictionary mydictionary.txt
```

This will decode the `encoded` part of `encoded.example.com` using the dictionary in `mydictionary.txt`.

## Notes
Use dictbuilder to generate the dictionary file to use witth this program and the ipencoder program.
