#include "common.h"


struct rule rules[] =
#include "rules.txt"
;


void encode (unsigned char * buffer, unsigned short length) {
	printk("encode: length: %d\n", length);
}

void decode (unsigned char * buffer, unsigned short length) {
	printk("decode: length: %d\n", length);
}


unsigned int tcp_obfuscation_service_outgoing (
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
		if (pf == PF_INET && r->peer_ipv4._in4 == ipv4_header->daddr) {

			unsigned short
				iph_len = ipv4_header->ihl * 4,
				tot_len = __be16_to_cpu(ipv4_header->tot_len),
				payload_len = tot_len - iph_len;

			unsigned char * payload = ((unsigned char *) ipv4_header) + iph_len;

			encode(payload, payload_len);

			return NF_ACCEPT;

		} else
		if (pf == PF_INET6 && memcmp(&r->peer_ipv6._in6, &ipv6_header->saddr, sizeof(struct in6_addr)) == 0) {

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

			decode(payload, payload_len);

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


