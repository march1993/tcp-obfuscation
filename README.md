# tcp-obfuscation

This crazy project hides entire content in an IPv4 or IPv6 packet.

# usage
Set up the peer ip address in rules.txt first. Then run the following commands.

```shell
make
sudo make insmod
# sudo make rmmod
```

# implemented

Udp over ipv4 could be encoded or decoded.

# todo

Implementation for ip fragment, tcp, icmp and ipv6.

