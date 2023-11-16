# arpmon

arpmon is a Go-based network tool designed for capturing and logging ARP (Address Resolution Protocol) packets on a specified network device. It provides real-time monitoring and logging of ARP traffic for network diagnostics and security analysis.


## Features

- Captures ARP packets on a specified network device.
- Configurable packet capture settings (device, snapshot length, promiscuous mode, timeout).
- Customizable logging options (file name prefix, log directory, max lines per file, log rotation time).
- Outputs ARP packet information in JSON format for easy parsing and analysis.


## Usage

```
./arpmon -device <network-device> -snaplen <snapshot-length> -promisc <true|false> -timeout <timeout-in-seconds>
```