#include "common.h"

static struct nf_hook_ops tcp_obfuscation_ops_ipv4_incoming =
{
	.hook = tcp_obfuscation_service_incoming,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops tcp_obfuscation_ops_ipv4_outgoing =
{
	.hook = tcp_obfuscation_service_outgoing,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST,
};

static int __init init_tcp_obfuscation_ipv4(void)
{
	printk(KERN_INFO "tcp_obfuscation: nf_register_hook for ipv4 ...\n");
	nf_register_hook(&tcp_obfuscation_ops_ipv4_incoming);
	nf_register_hook(&tcp_obfuscation_ops_ipv4_outgoing);

	return 0;
}

static void __exit exit_tcp_obfuscation_ipv4(void)
{
	printk(KERN_INFO "tco_obfuscation: nf_unregister_hook for ipv4 ...\n");
	nf_unregister_hook(&tcp_obfuscation_ops_ipv4_incoming);
	nf_unregister_hook(&tcp_obfuscation_ops_ipv4_outgoing);
}

module_init(init_tcp_obfuscation_ipv4);
module_exit(exit_tcp_obfuscation_ipv4);
