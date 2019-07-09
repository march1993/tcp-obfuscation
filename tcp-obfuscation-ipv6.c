#include "common.h"

static struct nf_hook_ops tcp_obfuscation_ops_ipv6_incoming = {
    .hook = tcp_obfuscation_service_incoming,
    .pf = PF_INET6,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops tcp_obfuscation_ops_ipv6_outgoing = {
    .hook = tcp_obfuscation_service_outgoing,
    .pf = PF_INET6,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_LAST,
};

static int __init init_tcp_obfuscation_ipv6(void) {
  printk(KERN_INFO "tcp_obfuscation: nf_register_hook for ipv6 ...\n");
  nf_register_net_hook(&init_net, &tcp_obfuscation_ops_ipv6_incoming);
  nf_register_net_hook(&init_net, &tcp_obfuscation_ops_ipv6_outgoing);

  return 0;
}

static void __exit exit_tcp_obfuscation_ipv6(void) {
  printk(KERN_INFO "tco_obfuscation: nf_unregister_hook for ipv6 ...\n");
  nf_unregister_net_hook(&init_net, &tcp_obfuscation_ops_ipv6_incoming);
  nf_unregister_net_hook(&init_net, &tcp_obfuscation_ops_ipv6_outgoing);
}

module_init(init_tcp_obfuscation_ipv6);
module_exit(exit_tcp_obfuscation_ipv6);
