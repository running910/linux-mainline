#include <linux/init.h>		// for __init and subsys_initcall
#include <linux/types.h>	// for u32
#include <linux/inet.h>		// for in_aton()	
#include <linux/module.h>	// optional, for module-related macros
#include <linux/kernel.h>	// for printk
#include <linux/sysctl.h>	// for sysctl
#include <linux/string.h>	// for string operations
#include <linux/ctype.h>	// for isspace()
#include <linux/export.h>	// for EXPORT_SYMBOL
#include <linux/ipv6.h>		// for struct in6_addr

u32 netlog_remote_addr __read_mostly;
EXPORT_SYMBOL(netlog_remote_addr);

u32 netlog_inner_addr __read_mostly;
EXPORT_SYMBOL(netlog_inner_addr);

u32 netlog_enable __read_mostly;
EXPORT_SYMBOL(netlog_enable);

struct in6_addr netlog6_remote_addr __read_mostly;
EXPORT_SYMBOL(netlog6_remote_addr);

struct in6_addr netlog6_inner_addr __read_mostly;
EXPORT_SYMBOL(netlog6_inner_addr);

u32 netlog6_enable __read_mostly;
EXPORT_SYMBOL(netlog6_enable);

#define MAX_NETLOG_STR_LEN	128

static int strip_whitespace(char *str)
{
	int i = 0, j = 0;
	while (str[i]) {
		if (!isspace(str[i])) {
			str[j++] = str[i];
		}
		i++;
	}
	str[j] = '\0';
	return j;
}

static void format_netlog_value(char *buf, size_t len)
{
	snprintf(buf, len, "%d,%pI4,%pI4", 
		netlog_enable,
		&netlog_remote_addr,
		&netlog_inner_addr);
}

static void format_netlog6_value(char *buf, size_t len)
{
	snprintf(buf, len, "%d,%pI6c,%pI6c",
		netlog6_enable,
		&netlog6_remote_addr,
		&netlog6_inner_addr);
}

static int parse_netlog6_addr(const char *str, struct in6_addr *addr)
{
	if (!str || !addr)
		return -EINVAL;

	if (in6_pton(str, -1, addr->s6_addr, -1, NULL) <= 0)
		return -EINVAL;

	return 0;
}

static int proc_netlog_handler(struct ctl_table *table, int write,
			      void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	bool enable;
	char data[MAX_NETLOG_STR_LEN] = {0};
	char *token;
	char *ptr = data;
	struct ctl_table tmp = {
		.data = data,
		.maxlen = sizeof(data),
	};

	if (!write) {
		char output[MAX_NETLOG_STR_LEN] = {0};
		format_netlog_value(output, sizeof(output));
		tmp.data = output;
		tmp.maxlen = sizeof(output);
		return proc_dostring(&tmp, write, buffer, lenp, ppos);
	}

	ret = proc_dostring(&tmp, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	/* Remove all whitespace */
	strip_whitespace(data);

	/* Parse enable flag */
	token = strsep(&ptr, ",");
	if (!token)
		return -EINVAL;
	
	if (kstrtobool(token, &enable))
		return -EINVAL;

	/* Parse remote address */
	token = strsep(&ptr, ",");
	if (!token)
		return -EINVAL;
	
	netlog_remote_addr = in_aton(token);
	if (!netlog_remote_addr)
		return -EINVAL;

	/* Parse inner address */
	token = strsep(&ptr, ",");
	if (!token)
		return -EINVAL;
	
	netlog_inner_addr = in_aton(token);
	if (!netlog_inner_addr)
		return -EINVAL;

	netlog_enable = enable;

	return 0;
}

static int proc_netlog6_handler(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	bool enable;
	char data[MAX_NETLOG_STR_LEN] = {0};
	char *token;
	char *ptr = data;
	struct in6_addr remote_addr;
	struct in6_addr inner_addr;
	struct ctl_table tmp = {
		.data = data,
		.maxlen = sizeof(data),
	};

	if (!write) {
		char output[MAX_NETLOG_STR_LEN] = {0};

		format_netlog6_value(output, sizeof(output));
		tmp.data = output;
		tmp.maxlen = sizeof(output);
		return proc_dostring(&tmp, write, buffer, lenp, ppos);
	}

	ret = proc_dostring(&tmp, write, buffer, lenp, ppos);
	if (ret || !write)
		return ret;

	strip_whitespace(data);

	token = strsep(&ptr, ",");
	if (!token)
		return -EINVAL;

	if (kstrtobool(token, &enable))
		return -EINVAL;

	token = strsep(&ptr, ",");
	if (!token)
		return -EINVAL;

	ret = parse_netlog6_addr(token, &remote_addr);
	if (ret)
		return ret;

	token = strsep(&ptr, ",");
	if (!token)
		return -EINVAL;

	ret = parse_netlog6_addr(token, &inner_addr);
	if (ret)
		return ret;

	netlog6_enable = enable;
	netlog6_remote_addr = remote_addr;
	netlog6_inner_addr = inner_addr;

	return 0;
}

static struct ctl_table net_core_table[] = {
	{
		.procname	= "netlog",
		.mode		= 0644,
		.proc_handler	= proc_netlog_handler,
	},
	{
		.procname	= "netlog6",
		.mode		= 0644,
		.proc_handler	= proc_netlog6_handler,
	},
	{}
};

static struct ctl_table net_table[] = {
	{
		.procname	= "core",
		.mode		= 0555,
		.child		= net_core_table,
	},
	{}
};

static struct ctl_table root_table[] = {
	{
		.procname	= "net",
		.mode		= 0555,
		.child		= net_table,
	},
	{}
};

static void __init net_debug_init(void)
{
	register_sysctl_table(root_table);
	
	netlog_enable = 0;
	netlog_remote_addr = in_aton("10.9.8.2");
	netlog_inner_addr = in_aton("192.168.1.147");
	netlog6_enable = 0;
	memset(&netlog6_remote_addr, 0, sizeof(netlog6_remote_addr));
	memset(&netlog6_inner_addr, 0, sizeof(netlog6_inner_addr));
}
subsys_initcall(net_debug_init);
