#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/proc_fs.h>


#define DOMAINS_BUF_LEN 512
#define MAX_DOMAINS     20
#define UDP_PAYLOAD_MAX_LEN 4096

struct garble_config {
	char domain_buf[DOMAINS_BUF_LEN];       // 域名参数buffer，会被strtep切开
	char *domain_list[MAX_DOMAINS];         // 域名列表，每个元素指向domain_buf被strsep切开的域名
	int num_domains;                        // 域名列表里的域名数量
	struct rcu_head rcu;                    // RCU删除钩子
};

static int garble_enabled = 0;
static char garble_args[DOMAINS_BUF_LEN] = "";
static int garble_http_enabled = 0;
static int garble_udp_enabled = 0;
static int garble_tcp_aggressive = 0;
static int garble_tcp_avg_pkt = 0;
static int garble_udp_aggressive = 0;
static int garble_udp_avg_pkt = 0;
static int garble_tcp_client_enabled = 0;
static int garble_udp_binary_payload = 0;
static int garble_udp_ttl = 3;              // Default TTL value for UDP packets
static int garble_udp_obf_proto = 0;          // UDP obfuscation proto: 0=stun allocate request, 1=wechat live video, 2=sip invite

static struct garble_config __rcu *garble_cfg_ptr = NULL;

static DEFINE_SPINLOCK(garble_cfg_lock);

static struct {
	char data[UDP_PAYLOAD_MAX_LEN];
	int len;
} udp_payload_data = {
	.len = 0,
	.data = {0}
};


static void garble_config_free(struct rcu_head *head)
{
        struct garble_config *cfg = container_of(head, struct garble_config, rcu);
        kfree(cfg);
}

static int proc_handler_udp_ttl(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	int new_ttl;

	if (!write) {
		return proc_dointvec(table, write, buffer, lenp, ppos);
	}

	struct ctl_table tmp_table = {
		.data = &new_ttl,
		.maxlen = sizeof(int),
	};

	ret = proc_dointvec(&tmp_table, write, buffer, lenp, ppos);
	if (ret != 0) {
		return ret;
	}

	/* Validate TTL range [3, 128] */
	if (new_ttl < 3 || new_ttl > 128) {
		pr_info("garble: UDP TTL value %d is out of range [3, 128]\n", new_ttl);
		return -EINVAL;
	}

	/* Update the actual TTL value */
	*(int *)table->data = new_ttl;
	pr_info("garble: UDP TTL updated to %d\n", new_ttl);

	return 0;
}

static int proc_handler_udp_obf_proto(struct ctl_table *table, int write,
				    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	int new_obf_pro;

	if (!write) {
		return proc_dointvec(table, write, buffer, lenp, ppos);
	}

	struct ctl_table tmp_table = {
		.data = &new_obf_pro,
		.maxlen = sizeof(int),
	};

	ret = proc_dointvec(&tmp_table, write, buffer, lenp, ppos);
	if (ret != 0) {
		return ret;
	}

	/* Validate obfuscation proto range [0, 2] */
	if (new_obf_pro < 0 || new_obf_pro > 2) {
		pr_info("garble: UDP obfuscation proto value %d is out of range [0, 2]\n", new_obf_pro);
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

static ssize_t udp_payload_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	ssize_t ret;

	if (*ppos >= UDP_PAYLOAD_MAX_LEN)
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
	if (count > UDP_PAYLOAD_MAX_LEN)
		return -EFBIG;

	if (copy_from_user(udp_payload_data.data, buf, count)) {
		return -EFAULT;
	}

	udp_payload_data.len = count;
	*ppos = count;

	pr_info("garble: udp_payload updated, length = %zu\n", count);
	return count;
}

static const struct proc_ops udp_payload_proc_ops = {
	.proc_read	= udp_payload_read,
	.proc_write	= udp_payload_write,
};

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
		.proc_handler	= proc_handler_udp_ttl,
	},
	{
		.procname	= "udp_obf_proto",
		.data		= &garble_udp_obf_proto,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_handler_udp_obf_proto,
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

int garble_sysctl_init(void)
{
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

        return 0;
}

void garble_sysctl_exit(void)
{
	struct garble_config *cfg;
	unsigned long flags;

	unregister_sysctl_table(garble_sysctl_header);

	/* Remove procfs entries */
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
}

inline bool garble_check_if_tcp_enabled(void)
{
	return garble_enabled || garble_http_enabled;
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
	return !garble_enabled && !garble_http_enabled;
}

inline bool garble_check_if_udp_enabled(void)
{
	return garble_udp_enabled;
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

inline bool garble_check_if_tcp_client_enabled(void)
{
	return garble_tcp_client_enabled;
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
