#include "common.h"


struct rule rules[] =
#include "rules.txt"
;
const unsigned n_rules = sizeof(rules) / sizeof(struct rule);


void encode (unsigned char * buffer, unsigned short length) {

	unsigned char * p;

	for (p = buffer; p < buffer + length; p++) {

		* p = 0x40 - * p;

	}

}

void decode (unsigned char * buffer, unsigned short length) {

	unsigned char * p;

	for (p = buffer; p < buffer + length; p++) {

		* p = 0x40 - * p;

	}

}


unsigned int tcp_obfuscation_service_outgoing (
	void * priv,
	struct sk_buff * skb,
	const struct nf_hook_state * state) {

	struct iphdr * ipv4_header;
	struct ipv6hdr * ipv6_header;
	/* protocol family */
	u_int8_t pf;
	unsigned i;

	if (unlikely(0 != skb_linearize(skb))) {

		return NF_DROP;

	}

	pf = state->pf;
	ipv4_header = ip_hdr(skb);
	ipv6_header = ipv6_hdr(skb);

	for (i = 0; i < n_rules; i ++) {

		struct rule * r = rules + i;

		/* rule's protocol should be equal to packet's protocol */
		if (r->protocol != pf) {

			continue;

		}


		/* address should match */
		if (PF_INET == pf && r->peer_ipv4._in4 == ipv4_header->daddr) {

			unsigned short
				iph_len = ipv4_header->ihl * 4,
				tot_len = ntohs(ipv4_header->tot_len),
				payload_len = tot_len - iph_len;

			unsigned char * payload = ((unsigned char *) ipv4_header) + iph_len;

			/* disable GSO */
			skb_gso_reset(skb);
			if (NULL != skb->sk) {

				/* I believe net_gso_ok has bug! */
				skb->sk->sk_gso_type = ~0;
				skb->sk->sk_gso_max_size = 0;

			}

			/* disable checksum */
			skb->ip_summed = CHECKSUM_UNNECESSARY;

			/* calc the checksum manually */
			if (IPPROTO_UDP == ipv4_header->protocol) {

				__wsum csum;
				struct udphdr * uh;
				int len;
				int offset;

				offset = skb_transport_offset(skb);
				len = skb->len - offset;
				uh = udp_hdr(skb);

				uh->check = 0;
				csum = csum_partial(payload, payload_len, 0);

				if (r->ipv4_behind_nat) {

					uh->check = csum_tcpudp_magic(r->nat_ipv4._in4, ipv4_header->daddr, len, IPPROTO_UDP, csum);

				} else {

					uh->check = csum_tcpudp_magic(ipv4_header->saddr, ipv4_header->daddr, len, IPPROTO_UDP, csum);

				}

				if (0 == uh->check) {

					uh->check = CSUM_MANGLED_0;

				}

				ipv4_header->protocol = DUMMY_UDP;

			} else
			if (IPPROTO_TCP == ipv4_header->protocol) {

				__wsum csum;
				struct tcphdr * th;

				th = tcp_hdr(skb);

				th->check = 0;
				csum = csum_partial(payload, payload_len, 0);

				if (r->ipv4_behind_nat) {

					th->check = csum_tcpudp_magic(r->nat_ipv4._in4, ipv4_header->daddr, payload_len, IPPROTO_TCP, csum);

				} else {

					th->check = csum_tcpudp_magic(ipv4_header->saddr, ipv4_header->daddr, payload_len, IPPROTO_TCP, csum);

				}

				ipv4_header->protocol = DUMMY_TCP;

			} else {

				/* For future other protocols needing checksum */

			}

			encode(payload, payload_len);

			ipv4_header->check = 0;
			ipv4_header->check = ip_fast_csum((unsigned char *) ipv4_header, ipv4_header->ihl);

			return NF_ACCEPT;

		} else
		if (PF_INET6 == pf && 0 == memcmp(&r->peer_ipv6._in6, &ipv6_header->saddr, sizeof(struct in6_addr))) {

			/* TODO: IPv6 */
			/* sk->no_check6_tx = 1; */
			return NF_ACCEPT;

		}

	}

	return NF_ACCEPT;

}




unsigned int tcp_obfuscation_service_incoming (
	void * priv,
	struct sk_buff * skb,
	const struct nf_hook_state * state) {

	struct iphdr * ipv4_header;
	struct ipv6hdr * ipv6_header;
	struct net_device * dev = skb->dev;
	struct net * net = dev_net(dev);
	/* protocol family */
	u_int8_t pf;
	unsigned i;

	if (unlikely(0 != skb_linearize(skb))) {

		return NF_DROP;

	}

	pf = state->pf;

	ipv4_header = ip_hdr(skb);
	ipv6_header = ipv6_hdr(skb);

	for (i = 0; i < n_rules; i ++) {

		struct rule * r = rules + i;

		// rule's protocol should be equal to packet's protocol
		if (r->protocol != pf) {

			continue;

		}

		// address should match
		if (PF_INET == pf && r->peer_ipv4._in4 == ipv4_header->saddr) {

			unsigned short iph_len, tot_len, payload_len;
			unsigned char * payload;

			if (ip_is_fragment(ipv4_header)) {

				// still collecting fragments
				if (ip_defrag(net, skb, IP_DEFRAG_CONNTRACK_IN)) {

					return NF_STOLEN;

				}

				// update skb and ipv4_header
				if (unlikely(0 != skb_linearize(skb))) {

					return NF_DROP;

				}
				ipv4_header = ip_hdr(skb);

			}

			iph_len = ipv4_header->ihl * 4;
			tot_len = ntohs(ipv4_header->tot_len);
			payload_len = tot_len - iph_len;
			payload = ((unsigned char *) ipv4_header) + iph_len;

			decode(payload, payload_len);

			/* disable checksum */
			skb->ip_summed = CHECKSUM_NONE;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 12, 0)
			skb->csum_bad = 0;
#endif

			if (ipv4_header->protocol == DUMMY_UDP) {

				struct udphdr * uh = udp_hdr(skb);

				ipv4_header->protocol = IPPROTO_UDP;

				if (r->ipv4_behind_nat) {

					unsigned long csum = uh->check;
					csum = csum - ~(0xFFFF & r->nat_ipv4._in4) - (0xFFFF & ipv4_header->daddr);
					csum = csum - ~(r->nat_ipv4._in4 >> 16) - (ipv4_header->daddr >> 16);
					csum = (csum >> 16) + (csum & 0xFFFF);
					csum +=  (csum >> 16);
					uh->check = (unsigned short) csum;

				}

			} else
			if (ipv4_header->protocol == DUMMY_TCP) {

				struct tcphdr * tp = tcp_hdr(skb);

				ipv4_header->protocol = IPPROTO_TCP;

				if (r->ipv4_behind_nat) {

					unsigned long csum = tp->check;
					csum = csum - ~(0xFFFF & r->nat_ipv4._in4) - (0xFFFF & ipv4_header->daddr);
					csum = csum - ~(r->nat_ipv4._in4 >> 16) - (ipv4_header->daddr >> 16);
					csum = (csum >> 16) + (csum & 0xFFFF);
					csum +=  (csum >> 16);
					tp->check = (unsigned short) csum;

				}

			} else {

				/* For future other protocols needing checksum */

			}

			return NF_ACCEPT;

		} else
		if (PF_INET6 == pf && 0 == memcmp(&r->peer_ipv6._in6, &ipv6_header->saddr, sizeof(struct in6_addr))) {

			// TODO: IPv6 Support
			return NF_ACCEPT;

		}

	}

	return NF_ACCEPT;

}





EXPORT_SYMBOL(tcp_obfuscation_service_incoming);
EXPORT_SYMBOL(tcp_obfuscation_service_outgoing);


