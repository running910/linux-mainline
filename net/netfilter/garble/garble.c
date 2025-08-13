#include <linux/kernel.h>
#include <linux/module.h>

#include "sysctl.h"

static __exit void nf_garble_exit(void)
{
	printk("************* nf_garble_exit");	

	garble_sysctl_exit();

}

static __exit int nf_garble_init(void)
{
        printk("************* nf_garble_init");

        garble_sysctl_init();

        return 0;
}

module_init(nf_garble_init);
module_exit(nf_garble_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("running910@gmail.com");
