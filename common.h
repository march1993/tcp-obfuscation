#include <linux/init.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <net/udp.h>

__u8 DUMMY_TCP = 0xFD, DUMMY_UDP = 0xFE, DUMMY_ICMP = 0xFC;

enum PROTOCOL {
  IPv4 = PF_INET,
  IPv6 = PF_INET6,
};

union in4 {
  unsigned char in4[4];
  __be32 _in4;
};

union in6 {
  unsigned char in6[16];
  struct in6_addr _in6;
};

struct rule {

  enum PROTOCOL protocol;
  union {
    union in4 peer_ipv4;
    union in6 peer_ipv6;
  };
  struct {
    bool ipv4_behind_nat;
    union in4 nat_ipv4;
  };
};

extern unsigned int
tcp_obfuscation_service_incoming(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state);

extern unsigned int
tcp_obfuscation_service_outgoing(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state);
