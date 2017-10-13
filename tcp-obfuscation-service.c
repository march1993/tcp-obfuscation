#include "common.h"


struct rule rules[] =
#include "rules.txt"
;

/* dangerous: only for debug */
static char buf[500];
void print_buffer(unsigned char * buffer, unsigned short length) {
	int i;
	char * start = buf;
	for (i = 0; i < length; i++) {
		start += sprintf(start, "%02x ", buffer[i]);

	}
	printk("buffer: %s\n", buf);
}

void encode (unsigned char * buffer, unsigned short length) {

	unsigned char * p;
	print_buffer(buffer, length);
	for (p = buffer; p < buffer + length; p++) {
	
		* p = 0x40 - * p;

	}

	printk("encoding [%d]\n", length);
	print_buffer(buffer, length);

}

void decode (unsigned char * buffer, unsigned short length) {

	unsigned char * p;
	print_buffer(buffer, length);
	for (p = buffer; p < buffer + length; p++) {
	
		* p = 0x40 - * p;

	}

	printk("decoding [%d]\n", length);
	print_buffer(buffer, length);

}


unsigned int tcp_obfuscation_service_outgoing (
	void * priv,
	struct sk_buff * skb,
	const struct nf_hook_state * state) {

	struct iphdr * ipv4_header;
	struct ipv6hdr * ipv6_header;
	/* protocol family */
	u_int8_t pf;
	const unsigned n_rules = sizeof(rules) / sizeof(struct rule);
	unsigned i;

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
		if (pf == PF_INET && r->peer_ipv4._in4 == ipv4_header->daddr) {

			unsigned short
				iph_len = ipv4_header->ihl * 4,
				tot_len = __be16_to_cpu(ipv4_header->tot_len),
				payload_len = tot_len - iph_len;

			unsigned char * payload = ((unsigned char *) ipv4_header) + iph_len;

			if (unlikely(skb_linearize(skb) != 0)) {

				return NF_DROP;

			}


			/* calc the checksum manually */
			if (ipv4_header->protocol == IPPROTO_UDP) {

				__wsum csum;
				struct udphdr * uh;
				int len;
				int offset;

				skb->sk->sk_no_check_tx = 1;
				skb->ip_summed = CHECKSUM_NONE;

				offset = skb_transport_offset(skb);
				len = skb->len - offset;
				uh = udp_hdr(skb);

				uh->check = 0;
				csum = csum_partial(payload, payload_len, 0);
				uh->check = csum_tcpudp_magic(ipv4_header->saddr, ipv4_header->daddr, len, IPPROTO_UDP, csum);
				if (uh->check == 0) {

					uh->check = CSUM_MANGLED_0;

				}

			} else
			if (ipv4_header->protocol == IPPROTO_TCP) {

				skb->ip_summed = CHECKSUM_UNNECESSARY;

			} else {

				/* unsupported protocol, maybe TODO: ICMP */

			}

			encode(payload, payload_len);

			return NF_ACCEPT;

		} else
		if (pf == PF_INET6 && memcmp(&r->peer_ipv6._in6, &ipv6_header->saddr, sizeof(struct in6_addr)) == 0) {

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
	// protocol family
	u_int8_t pf;
	const unsigned n_rules = sizeof(rules) / sizeof(struct rule);
	unsigned i;

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
		if (pf == PF_INET && r->peer_ipv4._in4 == ipv4_header->saddr) {

			unsigned short
				iph_len = ipv4_header->ihl * 4,
				tot_len = __be16_to_cpu(ipv4_header->tot_len),
				payload_len = tot_len - iph_len;

			unsigned char * payload = ((unsigned char *) ipv4_header) + iph_len;

			if (unlikely(skb_linearize(skb) != 0)) {

				return NF_DROP;

			}

			decode(payload, payload_len);

			/* calc the checksum manually */
			if (ipv4_header->protocol == IPPROTO_UDP) {

				__wsum csum;
				int len;
				int offset;

				skb->ip_summed = CHECKSUM_UNNECESSARY;

				offset = skb_transport_offset(skb);
				len = skb->len - offset;

				csum = csum_partial(payload, payload_len, 0);
				printk("csum0: %08x\n", csum);
				csum = csum_tcpudp_magic(ipv4_header->saddr, ipv4_header->daddr, len, IPPROTO_UDP, csum);
				printk("csum1: %08x\n", csum);

				if (csum != 0) {
					
					printk(KERN_INFO "NF_DROP...\n");
					return NF_DROP;

				}

			} else
			if (ipv4_header->protocol == IPPROTO_TCP) {

				skb->ip_summed = CHECKSUM_UNNECESSARY;

			} else {

				/* unsupported protocol, maybe TODO: ICMP */

			}

			return NF_ACCEPT;

		} else
		if (pf == PF_INET6 && memcmp(&r->peer_ipv6._in6, &ipv6_header->saddr, sizeof(struct in6_addr)) == 0) {

			return NF_ACCEPT;

		}

	}

	return NF_ACCEPT;

}





EXPORT_SYMBOL(tcp_obfuscation_service_incoming);
EXPORT_SYMBOL(tcp_obfuscation_service_outgoing);


