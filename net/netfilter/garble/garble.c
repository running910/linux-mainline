#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>

#include <net/netfilter/nf_garble.h>

#include "sysctl.h"
#include "stun.h"
#include "hook.h"
#include "nfhook.h"

static const struct nf_garble_ops nf_garble_ops = {
        .insert_tcp_packet = garble_insert_tcp_packet,
        .insert_tcp_packet_v6 = garble_insert_tcp_packet_v6,
        .insert_udp_packet_aggressive = garble_insert_udp_packet_aggressive,
        .insert_tcp_packet_aggressive = garble_insert_tcp_packet_aggressive,
        .insert_tcp_packet_client = garble_insert_tcp_packet_client,
};

static __exit void nf_garble_exit(void)
{
	printk("************* nf_garble_exit");	

        nf_garble_unregister_ops(&nf_garble_ops);

        garble_nfhook_exit();
        garble_sysctl_exit();
        stun_crypto_cleanup();

}

static __init int nf_garble_init(void)
{
        int err;

        printk("************* nf_garble_init");

        err = nf_garble_register_ops(&nf_garble_ops);
        if (err)
                return err;

	if (garble_nfhook_init())
                goto err_unregister_ops;

        garble_sysctl_init();
        stun_crypto_init();

        return 0;

err_unregister_ops:
        nf_garble_unregister_ops(&nf_garble_ops);
        return -EINVAL;
}

module_init(nf_garble_init);
module_exit(nf_garble_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("running910@gmail.com");
