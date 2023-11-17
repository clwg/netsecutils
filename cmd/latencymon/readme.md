# latencymon

Simple icmp monitor that reports latency and packet loss, like ping with some stats.

If you do not want to have to sudo then you can set the capabilities on the binary:

```bash
sudo setcap cap_net_raw=+ep ./latencymon
```