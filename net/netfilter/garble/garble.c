#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>

#include "sysctl.h"
#include "stun.h"
#include "nfhook.h"

static __exit void nf_garble_exit(void)
{
	printk("************* nf_garble_exit");	

        garble_routing_exit();
	garble_sysctl_exit();
        stun_crypto_cleanup();

}

static __exit int nf_garble_init(void)
{
        printk("************* nf_garble_init");

	if (garble_routing_init())
		return -EINVAL;

        garble_sysctl_init();
        stun_crypto_init();

        return 0;
}

module_init(nf_garble_init);
module_exit(nf_garble_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("running910@gmail.com");
