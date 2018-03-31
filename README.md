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

* TCP, UDP, ICMP over ipv4 could be encoded or decoded.
* Nat is supported. Note that netfilter would defrag the incoming packets, so that it is unnecessary to defrag again in our outgoing hook.
* IP fragmentation is supported.

# todo

Implementation for ipv6.

