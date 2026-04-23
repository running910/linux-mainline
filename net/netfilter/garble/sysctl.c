#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/proc_fs.h>
#include <linux/percpu.h>
#include <linux/uaccess.h>
#include <linux/u64_stats_sync.h>
#include <linux/version.h>
#include <linux/string.h>

#include "sysctl.h"


#define DOMAINS_BUF_LEN 1048576
#define MAX_DOMAINS     131072
#define UDP_EXTRA_BUF_LEN 512
#define LAN_NICS_BUF_LEN 512
#define MAX_LAN_NICS    20

struct garble_config {
	char domain_buf[DOMAINS_BUF_LEN];       // 域名参数buffer，会被strtep切开
	char *domain_list[MAX_DOMAINS];         // 域名列表，每个元素指向domain_buf被strsep切开的域名
	int num_domains;                        // 域名列表里的域名数量
	struct rcu_head rcu;                    // RCU删除钩子
};

struct garble_lan_config {
	char lan_buf[LAN_NICS_BUF_LEN];          // 网卡参数buffer，会被strsep切开
	char *lan_list[MAX_LAN_NICS];            // 网卡列表
	int num_lans;                           // 网卡数量
	struct rcu_head rcu;                    // RCU删除钩子
};

static int garble_enabled = 0;
static char garble_args[DOMAINS_BUF_LEN] = "";
static char garble_lan_args[LAN_NICS_BUF_LEN] = "br-virt,br-vmbr0";
static int garble_http_enabled = 0;
static int garble_udp_enabled = 0;
static int garble_tcp_aggressive = 0;
static int garble_tcp_avg_pkt = 0;
static int garble_tcp_repeat_pkt = 3;
static int garble_udp_aggressive = 0;
static int garble_udp_avg_pkt = 0;
static int garble_tcp_client_enabled = 0;
static int garble_local_obf_enabled = 0;
static int garble_wellknown_port_obf_enabled = 0;
static int garble_routing_enabled = 0;
static int garble_tcp_binary_payload = 0;
static int garble_udp_binary_payload = 0;
static int garble_udp_ttl = 3;                          // Default TTL value for UDP packets
static int garble_udp_obf_proto = 0;                    // UDP obfuscation proto: 0=stun allocate request, 1=wechat live video, 2=sip invite, 3=dtls client hello
static int garble_tcp_ttl = 3;                          // Default TTL value for TCP packets
static char garble_udp_extra[UDP_EXTRA_BUF_LEN] ={0};   // UDP extra configuration string

static struct garble_config __rcu *garble_cfg_ptr = NULL;
static struct garble_lan_config __rcu *garble_lan_cfg_ptr = NULL;

static DEFINE_SPINLOCK(garble_cfg_lock);
static DEFINE_SPINLOCK(garble_lan_cfg_lock);

static struct {
	char data[GARBLE_MAX_UDP_PAYLOAD];
	int len;
} udp_payload_data = {
	.len = 0,
	.data = {0}
};

static struct {
	char data[GARBLE_MAX_TCP_PAYLOAD];
	int len;
} tcp_payload_data = {
	.len = 0,
	.data = {0}
};

enum garble_stats_idx {
	GARBLE_STAT_TCP_V4 = 0,
	GARBLE_STAT_TCP_V6,
	GARBLE_STAT_UDP_V4,
	GARBLE_STAT_UDP_V6,
	GARBLE_STAT_MAX,
};

struct garble_pcpu_stats {
	struct u64_stats_sync syncp;
	u64 pkts[GARBLE_STAT_MAX];
	u64 bytes[GARBLE_STAT_MAX];
};

struct garble_stats_total {
	u64 pkts[GARBLE_STAT_MAX];
	u64 bytes[GARBLE_STAT_MAX];
};

static DEFINE_PER_CPU(struct garble_pcpu_stats, garble_pcpu_stats);


static void garble_config_free(struct rcu_head *head)
{
        struct garble_config *cfg = container_of(head, struct garble_config, rcu);
        kfree(cfg);
}

static void garble_lan_config_free(struct rcu_head *head)
{
	struct garble_lan_config *cfg = container_of(head, struct garble_lan_config, rcu);
	kfree(cfg);
}

static int proc_handler_ttl(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	int new_ttl;
	struct ctl_table tmp_table;

	if (!write) {
		return proc_dointvec(table, write, buffer, lenp, ppos);
	}

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.data = &new_ttl;
	tmp_table.maxlen = sizeof(int);

	ret = proc_dointvec(&tmp_table, write, buffer, lenp, ppos);
	if (ret != 0) {
		return ret;
	}

	/* Validate TTL range [3, 128] */
	if (new_ttl < 3 || new_ttl > 128) {
		pr_info("garble: %s value %d is out of range [3, 128]\n", table->procname, new_ttl);
		return -EINVAL;
	}

	/* Update the actual TTL value */
	*(int *)table->data = new_ttl;
	pr_info("garble: %s updated to %d\n", table->procname, new_ttl);

	return 0;
}

static int proc_handler_udp_obf_proto(struct ctl_table *table, int write,
				    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	int new_obf_pro;
	struct ctl_table tmp_table;

	if (!write) {
		return proc_dointvec(table, write, buffer, lenp, ppos);
	}

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.data = &new_obf_pro;
	tmp_table.maxlen = sizeof(int);

	ret = proc_dointvec(&tmp_table, write, buffer, lenp, ppos);
	if (ret != 0) {
		return ret;
	}

	/* Validate obfuscation proto range [0, UDP_OBF_PROTO_MAX - 1] */
	if (new_obf_pro < 0 || new_obf_pro >= UDP_OBF_PROTO_MAX) {
		pr_info("garble: UDP obfuscation proto value %d is out of range [0, %d]\n", new_obf_pro, UDP_OBF_PROTO_MAX - 1);
		return -EINVAL;
	}

	/* Update the actual obfuscation profile value */
	*(int *)table->data = new_obf_pro;
	pr_info("garble: UDP obfuscation proto updated to %d\n", new_obf_pro);

	return 0;
}

static int proc_handler_domains(struct ctl_table *table, int write,
                                void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct garble_config *new_cfg;
	struct garble_config *old_cfg;
	int ret;
	char *s;
	char *token;
	int i = 0;
	unsigned long flags;

	ret = proc_dostring(table, write, buffer, lenp, ppos);
	if (ret != 0 || !write)
		return ret;

	new_cfg = kzalloc(sizeof(*new_cfg), GFP_KERNEL);
	if (NULL == new_cfg)
		return -ENOMEM;

	/*
	 * strscpy确保domain_buf字符串以'\0'结束（其实kzalloc已经确保了最后一个字节必定为'\0'）
	 */
	if (strscpy(new_cfg->domain_buf, (char *)table->data, DOMAINS_BUF_LEN) < 0)
		return -EINVAL;

	/* 
	 * 解析成域名列表
	 */
	s = new_cfg->domain_buf;
	while (((token = strsep(&s, ",")) != NULL) && (i < MAX_DOMAINS)) {
		if (*token == '\0')
			continue;
		new_cfg->domain_list[i++] = token;
		printk(KERN_INFO "Domain[%d] = %s\n", i, token);
	}
	new_cfg->num_domains = i;

	pr_info("garble: updated %d domains\n", new_cfg->num_domains);

	spin_lock_irqsave(&garble_cfg_lock, flags);

	old_cfg = rcu_dereference_protected(garble_cfg_ptr, lockdep_is_held(&garble_cfg_lock));

	/*
	 * 待所有读者完成后用新指针new_cfg赋值到garble_cfg_ptr指针
	 */
	rcu_assign_pointer(garble_cfg_ptr, new_cfg);

	spin_unlock_irqrestore(&garble_cfg_lock, flags);

	if (NULL != old_cfg)
		call_rcu(&old_cfg->rcu, garble_config_free);


	return 0;
}

static struct garble_lan_config *garble_parse_lan_nics(const char *src)
{
	struct garble_lan_config *cfg;
	char *s;
	char *token;
	int i = 0;

	if (!src)
		return NULL;

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg)
		return NULL;

	if (strscpy(cfg->lan_buf, src, LAN_NICS_BUF_LEN) < 0) {
		kfree(cfg);
		return NULL;
	}

	s = cfg->lan_buf;
	while (((token = strsep(&s, ",")) != NULL) && (i < MAX_LAN_NICS)) {
		if (*token == '\0')
			continue;
		printk(KERN_INFO "garble: lan nic[%d] = %s\n", i, token);
		cfg->lan_list[i++] = token;
	}
	cfg->num_lans = i;

	pr_info("garble: updated %d lan_nics\n", cfg->num_lans);

	return cfg;
}

static int proc_handler_lan_nics(struct ctl_table *table, int write,
				 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct garble_lan_config *new_cfg;
	struct garble_lan_config *old_cfg;
	int ret;
	unsigned long flags;

	ret = proc_dostring(table, write, buffer, lenp, ppos);
	if (ret != 0 || !write)
		return ret;

	new_cfg = garble_parse_lan_nics((char *)table->data);
	if (!new_cfg)
		return -ENOMEM;

	spin_lock_irqsave(&garble_lan_cfg_lock, flags);
	old_cfg = rcu_dereference_protected(garble_lan_cfg_ptr,
					    lockdep_is_held(&garble_lan_cfg_lock));
	rcu_assign_pointer(garble_lan_cfg_ptr, new_cfg);
	spin_unlock_irqrestore(&garble_lan_cfg_lock, flags);

	if (old_cfg)
		call_rcu(&old_cfg->rcu, garble_lan_config_free);

	return 0;
}

static ssize_t udp_payload_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	ssize_t ret;

	if (*ppos >= GARBLE_MAX_UDP_PAYLOAD)
		return 0;

	if (*ppos >= udp_payload_data.len) {
		return 0;
	}

	if (count > udp_payload_data.len - *ppos)
		count = udp_payload_data.len - *ppos;

	if (copy_to_user(buf, udp_payload_data.data + *ppos, count)) {
		return -EFAULT;
	}

	*ppos += count;
	ret = count;

	return ret;
}

static ssize_t udp_payload_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	if (count > GARBLE_MAX_UDP_PAYLOAD)
		return -EFBIG;

	if (copy_from_user(udp_payload_data.data, buf, count)) {
		return -EFAULT;
	}

	udp_payload_data.len = count;
	*ppos = count;

	pr_info("garble: udp_payload updated, length = %zu\n", count);
	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops udp_payload_proc_ops = {
	.proc_read	= udp_payload_read,
	.proc_write	= udp_payload_write,
};
#else
static const struct file_operations udp_payload_proc_ops = {
	.owner		= THIS_MODULE,
	.read		= udp_payload_read,
	.write		= udp_payload_write,
};
#endif

static ssize_t tcp_payload_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	ssize_t ret;

	if (*ppos >= GARBLE_MAX_TCP_PAYLOAD)
		return 0;

	if (*ppos >= tcp_payload_data.len) {
		return 0;
	}

	if (count > tcp_payload_data.len - *ppos)
		count = tcp_payload_data.len - *ppos;

	if (copy_to_user(buf, tcp_payload_data.data + *ppos, count)) {
		return -EFAULT;
	}

	*ppos += count;
	ret = count;

	return ret;
}

static ssize_t tcp_payload_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	if (count > GARBLE_MAX_TCP_PAYLOAD)
		return -EFBIG;

	if (copy_from_user(tcp_payload_data.data, buf, count)) {
		return -EFAULT;
	}

	tcp_payload_data.len = count;
	*ppos = count;

	pr_info("garble: tcp_payload updated, length = %zu\n", count);
	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops tcp_payload_proc_ops = {
	.proc_read	= tcp_payload_read,
	.proc_write	= tcp_payload_write,
};
#else
static const struct file_operations tcp_payload_proc_ops = {
	.owner		= THIS_MODULE,
	.read		= tcp_payload_read,
	.write		= tcp_payload_write,
};
#endif

static struct ctl_table garble_table[] = {
        {
		.procname   = "enable",
		.data       = &garble_enabled,
		.maxlen     = sizeof(int),
		.mode       = 0644,
		.proc_handler = proc_dointvec,
        },
	{
		.procname   = "enable_http",
		.data       = &garble_http_enabled,
		.maxlen     = sizeof(int),
		.mode       = 0644,
		.proc_handler = proc_dointvec,
        },
	{
		.procname	= "enable_udp",
		.data		= &garble_udp_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "enable_tcp_aggressive",
		.data		= &garble_tcp_aggressive,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "enable_udp_aggressive",
		.data		= &garble_udp_aggressive,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "enable_tcp_client",
		.data		= &garble_tcp_client_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "enable_local_obf",
		.data		= &garble_local_obf_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "enable_wellknown_port_obf",
		.data		= &garble_wellknown_port_obf_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "enable_routing",
		.data		= &garble_routing_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "enable_tcp_binary_payload",
		.data		= &garble_tcp_binary_payload,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "enable_udp_binary_payload",
		.data		= &garble_udp_binary_payload,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "tcp_aggr_avg_pkt",
		.data		= &garble_tcp_avg_pkt,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "tcp_repeat_pkt",
		.data		= &garble_tcp_repeat_pkt,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "udp_aggr_avg_pkt",
		.data		= &garble_udp_avg_pkt,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "udp_ttl",
		.data		= &garble_udp_ttl,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_handler_ttl,
	},
	{
		.procname	= "tcp_ttl",
		.data		= &garble_tcp_ttl,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_handler_ttl,
	},
	{
		.procname	= "udp_obf_proto",
		.data		= &garble_udp_obf_proto,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_handler_udp_obf_proto,
	},
	{
		.procname	= "udp_extra",
		.data		= garble_udp_extra,
		.maxlen		= UDP_EXTRA_BUF_LEN,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "lan_nics",
		.data		= garble_lan_args,
		.maxlen		= DOMAINS_BUF_LEN,
		.mode		= 0644,
		.proc_handler	= proc_handler_lan_nics,
	},
        {
                .procname   = "domains",
                .data       = garble_args,
                .maxlen     = DOMAINS_BUF_LEN,
                .mode       = 0644,
                .proc_handler = proc_handler_domains,

        },
        {}
};

static struct ctl_table garble_net_table[] = {
        {
                .procname   = "garble",
                .mode       = 0555,
                .child      = garble_table,
        },
        {}
};

static struct ctl_table garble_net_root[] = {
        {
                .procname   = "net",
                .mode       = 0555,
                .child      = garble_net_table,
        },
        {}
};

static struct ctl_table_header *garble_sysctl_header;
static struct proc_dir_entry *garble_proc_dir;
static struct proc_dir_entry *udp_payload_proc_entry;
static struct proc_dir_entry *tcp_payload_proc_entry;
static struct proc_dir_entry *stats_proc_entry;

static inline void garble_stats_account(enum garble_stats_idx idx, u32 bytes)
{
	struct garble_pcpu_stats *stats;

	preempt_disable();
	stats = this_cpu_ptr(&garble_pcpu_stats);
	u64_stats_update_begin(&stats->syncp);
	stats->pkts[idx]++;
	stats->bytes[idx] += bytes;
	u64_stats_update_end(&stats->syncp);
	preempt_enable();
}

inline void garble_stats_account_tcp_v4(u32 bytes)
{
	garble_stats_account(GARBLE_STAT_TCP_V4, bytes);
}

inline void garble_stats_account_tcp_v6(u32 bytes)
{
	garble_stats_account(GARBLE_STAT_TCP_V6, bytes);
}

inline void garble_stats_account_udp_v4(u32 bytes)
{
	garble_stats_account(GARBLE_STAT_UDP_V4, bytes);
}

inline void garble_stats_account_udp_v6(u32 bytes)
{
	garble_stats_account(GARBLE_STAT_UDP_V6, bytes);
}

static void garble_stats_collect(struct garble_stats_total *total)
{
	int cpu, i;

	memset(total, 0, sizeof(*total));

	for_each_possible_cpu(cpu) {
		struct garble_pcpu_stats *stats;
		u64 pkts[GARBLE_STAT_MAX];
		u64 bytes[GARBLE_STAT_MAX];
		unsigned int start;

		stats = per_cpu_ptr(&garble_pcpu_stats, cpu);
		do {
			start = u64_stats_fetch_begin_irq(&stats->syncp);
			for (i = 0; i < GARBLE_STAT_MAX; i++) {
				pkts[i] = stats->pkts[i];
				bytes[i] = stats->bytes[i];
			}
		} while (u64_stats_fetch_retry_irq(&stats->syncp, start));

		for (i = 0; i < GARBLE_STAT_MAX; i++) {
			total->pkts[i] += pkts[i];
			total->bytes[i] += bytes[i];
		}
	}
}

static ssize_t garble_stats_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	char out[768];
	struct garble_stats_total total;
	u64 tcp_pkts, udp_pkts, ipv4_pkts, ipv6_pkts, all_pkts;
	u64 tcp_bytes, udp_bytes, ipv4_bytes, ipv6_bytes, all_bytes;
	int len;

	garble_stats_collect(&total);

	tcp_pkts = total.pkts[GARBLE_STAT_TCP_V4] + total.pkts[GARBLE_STAT_TCP_V6];
	udp_pkts = total.pkts[GARBLE_STAT_UDP_V4] + total.pkts[GARBLE_STAT_UDP_V6];
	ipv4_pkts = total.pkts[GARBLE_STAT_TCP_V4] + total.pkts[GARBLE_STAT_UDP_V4];
	ipv6_pkts = total.pkts[GARBLE_STAT_TCP_V6] + total.pkts[GARBLE_STAT_UDP_V6];
	all_pkts = tcp_pkts + udp_pkts;

	tcp_bytes = total.bytes[GARBLE_STAT_TCP_V4] + total.bytes[GARBLE_STAT_TCP_V6];
	udp_bytes = total.bytes[GARBLE_STAT_UDP_V4] + total.bytes[GARBLE_STAT_UDP_V6];
	ipv4_bytes = total.bytes[GARBLE_STAT_TCP_V4] + total.bytes[GARBLE_STAT_UDP_V4];
	ipv6_bytes = total.bytes[GARBLE_STAT_TCP_V6] + total.bytes[GARBLE_STAT_UDP_V6];
	all_bytes = tcp_bytes + udp_bytes;

	len = scnprintf(out, sizeof(out),
		"metric        packets             bytes\n"
		"total         %llu               %llu\n"
		"tcp           %llu               %llu\n"
		"udp           %llu               %llu\n"
		"ipv4          %llu               %llu\n"
		"ipv6          %llu               %llu\n"
		"tcp_v4        %llu               %llu\n"
		"tcp_v6        %llu               %llu\n"
		"udp_v4        %llu               %llu\n"
		"udp_v6        %llu               %llu\n",
		all_pkts, all_bytes,
		tcp_pkts, tcp_bytes,
		udp_pkts, udp_bytes,
		ipv4_pkts, ipv4_bytes,
		ipv6_pkts, ipv6_bytes,
		total.pkts[GARBLE_STAT_TCP_V4], total.bytes[GARBLE_STAT_TCP_V4],
		total.pkts[GARBLE_STAT_TCP_V6], total.bytes[GARBLE_STAT_TCP_V6],
		total.pkts[GARBLE_STAT_UDP_V4], total.bytes[GARBLE_STAT_UDP_V4],
		total.pkts[GARBLE_STAT_UDP_V6], total.bytes[GARBLE_STAT_UDP_V6]);

	return simple_read_from_buffer(buf, count, ppos, out, len);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops garble_stats_proc_ops = {
	.proc_read	= garble_stats_read,
};
#else
static const struct file_operations garble_stats_proc_ops = {
	.owner		= THIS_MODULE,
	.read		= garble_stats_read,
};
#endif

int garble_sysctl_init(void)
{
	struct garble_lan_config *default_lan_cfg;
	unsigned long flags;

        garble_sysctl_header = register_sysctl_table(garble_net_root);

        if (garble_sysctl_header) {
                printk("register_sysctl_table() success!");
        } else {
                printk("register_sysctl_table() failed!");
        }

	/* Create procfs directory and UDP payload entry */
	garble_proc_dir = proc_mkdir("garble", NULL);
	if (!garble_proc_dir) {
		pr_err("garble: failed to create /proc/garble directory\n");
		return -ENOMEM;
	}

	udp_payload_proc_entry = proc_create("udp_payload", 0644, garble_proc_dir, &udp_payload_proc_ops);
	if (!udp_payload_proc_entry) {
		pr_err("garble: failed to create /proc/garble/udp_payload entry\n");
		remove_proc_entry("garble", NULL);
		return -ENOMEM;
	}

	tcp_payload_proc_entry = proc_create("tcp_payload", 0644, garble_proc_dir, &tcp_payload_proc_ops);
	if (!tcp_payload_proc_entry) {
		pr_err("garble: failed to create /proc/garble/tcp_payload entry\n");
		remove_proc_entry("udp_payload", garble_proc_dir);
		remove_proc_entry("garble", NULL);
		return -ENOMEM;
	}

	stats_proc_entry = proc_create("stats", 0444, garble_proc_dir,
				      &garble_stats_proc_ops);
	if (!stats_proc_entry) {
		pr_err("garble: failed to create /proc/garble/stats entry\n");
		remove_proc_entry("tcp_payload", garble_proc_dir);
		remove_proc_entry("udp_payload", garble_proc_dir);
		remove_proc_entry("garble", NULL);
		return -ENOMEM;
	}

	default_lan_cfg = garble_parse_lan_nics(garble_lan_args);
	if (!default_lan_cfg)
		return -ENOMEM;

	spin_lock_irqsave(&garble_lan_cfg_lock, flags);
	rcu_assign_pointer(garble_lan_cfg_ptr, default_lan_cfg);
	spin_unlock_irqrestore(&garble_lan_cfg_lock, flags);

        return 0;
}

void garble_sysctl_exit(void)
{
	struct garble_config *cfg;
	struct garble_lan_config *lan_cfg;
	unsigned long flags;

	unregister_sysctl_table(garble_sysctl_header);

	/* Remove procfs entries */
	if (stats_proc_entry)
		remove_proc_entry("stats", garble_proc_dir);
	if (tcp_payload_proc_entry)
		remove_proc_entry("tcp_payload", garble_proc_dir);
	if (udp_payload_proc_entry)
		remove_proc_entry("udp_payload", garble_proc_dir);
	if (garble_proc_dir)
		remove_proc_entry("garble", NULL);

	spin_lock_irqsave(&garble_cfg_lock, flags);
	cfg = rcu_dereference_protected(garble_cfg_ptr, lockdep_is_held(&garble_cfg_lock));
	rcu_assign_pointer(garble_cfg_ptr, NULL);
	spin_unlock_irqrestore(&garble_cfg_lock, flags);

	if (NULL != cfg)
		call_rcu(&cfg->rcu, garble_config_free);

	spin_lock_irqsave(&garble_lan_cfg_lock, flags);
	lan_cfg = rcu_dereference_protected(garble_lan_cfg_ptr,
					    lockdep_is_held(&garble_lan_cfg_lock));
	rcu_assign_pointer(garble_lan_cfg_ptr, NULL);
	spin_unlock_irqrestore(&garble_lan_cfg_lock, flags);

	if (lan_cfg)
		call_rcu(&lan_cfg->rcu, garble_lan_config_free);
}

inline bool garble_check_if_tcp_enabled(void)
{
	return garble_enabled || garble_http_enabled || garble_tcp_binary_payload;
}

inline bool garble_check_if_tcp_aggressive(void)
{
	return garble_tcp_aggressive;
}

inline bool garble_check_if_tcp_double_enabled(void)
{
	return garble_enabled && garble_http_enabled;
}

inline bool garble_check_if_tls_enabled(void)
{
	return garble_enabled;
}

inline bool garble_check_if_http_enabled(void)
{
	return garble_http_enabled;
}

inline bool garble_check_if_tcp_disabled(void)
{
	return !garble_enabled && !garble_http_enabled && !garble_tcp_binary_payload;
}

inline bool garble_check_if_udp_enabled(void)
{
	return garble_udp_enabled;
}

inline bool garble_check_if_tcp_binary_enabled(void)
{
	return garble_tcp_binary_payload;
}

inline bool garble_check_if_udp_binary_enabled(void)
{
	return garble_udp_binary_payload;
}

inline bool garble_check_if_udp_aggressive(void)
{
	return garble_udp_aggressive;
}

inline int garble_get_udp_avg_pkt(void)
{
	return garble_udp_avg_pkt;
}

inline int garble_get_tcp_avg_pkt(void)
{
	return garble_tcp_avg_pkt;
}

inline int garble_get_tcp_repeat_pkt(void)
{
	return garble_tcp_repeat_pkt;
}

inline bool garble_check_if_tcp_client_enabled(void)
{
	return garble_tcp_client_enabled;
}

inline bool garble_check_if_local_obf_enabled(void)
{
	return garble_local_obf_enabled;
}

inline bool garble_check_if_wellknown_port_obf_enabled(void)
{
	return garble_wellknown_port_obf_enabled;
}

inline bool garble_check_if_routing_enabled(void)
{
	return garble_routing_enabled;
}

inline int garble_get_tcp_ttl(void)
{
	return garble_tcp_ttl;
}

inline int garble_get_udp_ttl(void)
{
	return garble_udp_ttl;
}

inline int garble_get_udp_obf_proto(void)
{
	return garble_udp_obf_proto;
}

inline const char *garble_get_random_domain(void)
{
	const char *domain = NULL;
	struct garble_config *cfg;

	rcu_read_lock();
	cfg = rcu_dereference(garble_cfg_ptr);
	if (cfg && (cfg->num_domains > 0))
		domain = cfg->domain_list[prandom_u32() % cfg->num_domains];
	rcu_read_unlock();

	return domain;
}

inline int garble_check_if_lan_nic(const char *nic)
{
	struct garble_lan_config *cfg;
	int i;
	int found = 0;

	if (!nic)
		return 0;

	rcu_read_lock();
	cfg = rcu_dereference(garble_lan_cfg_ptr);
	if (cfg && (cfg->num_lans > 0)) {
		for (i = 0; i < cfg->num_lans; i++) {
			if (cfg->lan_list[i] && !strcmp(cfg->lan_list[i], nic)) {
				found = 1;
				break;
			}
		}
	}
	rcu_read_unlock();

	return found;
}

inline const char *garble_get_udp_payload(int *len)
{
	if (udp_payload_data.len > 0) {
		*len = udp_payload_data.len;
		return udp_payload_data.data;
	} else {
		*len = 0;
		return NULL;
	}
}

inline const char *garble_get_tcp_payload(int *len)
{
	if (tcp_payload_data.len > 0) {
		*len = tcp_payload_data.len;
		return tcp_payload_data.data;
	} else {
		*len = 0;
		return NULL;
	}
}

inline const char *garble_get_udp_extra(void)
{
	if (garble_udp_extra[0] == '\0') {
		return NULL;
	} else {
		return garble_udp_extra;
	}
}
