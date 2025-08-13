#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/random.h>


#define DOMAINS_BUF_LEN 512
#define MAX_DOMAINS     20

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

static struct garble_config __rcu *garble_cfg_ptr = NULL;

static DEFINE_SPINLOCK(garble_cfg_lock);


static void garble_config_free(struct rcu_head *head)
{
        struct garble_config *cfg = container_of(head, struct garble_config, rcu);
        kfree(cfg);
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
	strscpy(new_cfg->domain_buf, (char *)table->data, DOMAINS_BUF_LEN);

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

int garble_sysctl_init(void)
{
        garble_sysctl_header = register_sysctl_table(garble_net_root);

        if (garble_sysctl_header) {
                printk("register_sysctl_table() success!");
        } else {
                printk("register_sysctl_table() failed!");
        }

        return 0;
}

void garble_sysctl_exit(void)
{
	struct garble_config *cfg;
	unsigned long flags;

	unregister_sysctl_table(garble_sysctl_header);

	spin_lock_irqsave(&garble_cfg_lock, flags);
	cfg = rcu_dereference_protected(garble_cfg_ptr, lockdep_is_held(&garble_cfg_lock));
	rcu_assign_pointer(garble_cfg_ptr, NULL);
	spin_unlock_irqrestore(&garble_cfg_lock, flags);

	if (NULL != cfg)
		call_rcu(&cfg->rcu, garble_config_free);
}

inline bool garble_check_if_enabled(void)
{
	return garble_enabled || garble_http_enabled;
}

inline bool garble_check_if_double_enabled(void)
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

inline bool garble_check_if_udp_enabled(void)
{
	return garble_udp_enabled;
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