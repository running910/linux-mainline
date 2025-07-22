#include <linux/init.h>        // for __init and subsys_initcall
#include <linux/types.h>       // for u32
#include <linux/inet.h>	       // for in_aton()	
#include <linux/module.h>      // optional, for module-related macros (if it's a module)
#include <linux/kernel.h>      // for printk (if logging is used)

u32 netlog_remote_addr __read_mostly;
EXPORT_SYMBOL(netlog_remote_addr);

u32 netlog_inner_addr __read_mostly;
EXPORT_SYMBOL(netlog_inner_addr);

static void __init net_debug_init(void)
{
	netlog_remote_addr = in_aton("10.9.8.2");
	netlog_inner_addr = in_aton("192.168.1.147");
}
subsys_initcall(net_debug_init);
