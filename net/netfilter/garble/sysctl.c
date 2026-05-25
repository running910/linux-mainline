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
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/mm.h>
#include <linux/seq_file.h>

#include "sysctl.h"


#define DOMAINS_BUF_LEN 1048576
#define MAX_DOMAINS     131072
#define UDP_EXTRA_BUF_LEN 512
#define UDP_OBF_PROTOS_BUF_LEN 256
#define TCP_OBF_PROTOS_BUF_LEN 256
#define LAN_NICS_BUF_LEN 512
#define MAX_LAN_NICS    20
#define GARBLE_PAYLOAD_FILE_NAME_LEN 64
#define GARBLE_PAYLOAD_FILE_CTL_BUF_LEN 128

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

struct garble_udp_obf_config {
	char proto_buf[UDP_OBF_PROTOS_BUF_LEN];
	unsigned long mask;
	int weights[UDP_OBF_PROTO_MAX];
	struct rcu_head rcu;
};

struct garble_tcp_obf_config {
	char proto_buf[TCP_OBF_PROTOS_BUF_LEN];
	unsigned long mask;
	int weights[TCP_OBF_PROTO_MAX];
	struct rcu_head rcu;
};

struct garble_payload_file {
	struct list_head list;
	struct rcu_head rcu;
	struct proc_dir_entry *entry;
	refcount_t refcnt;
	spinlock_t update_lock;
	bool removed;
	int max_len;
	char name[GARBLE_PAYLOAD_FILE_NAME_LEN];
	struct garble_payload_blob __rcu *blob;
};

struct garble_payload_blob {
	struct rcu_head rcu;
	char data[GARBLE_MAX_UDP_PAYLOAD];
	int len;
};

static int garble_enabled = 0;
static char garble_args[DOMAINS_BUF_LEN] = "";
static char garble_lan_args[LAN_NICS_BUF_LEN] = "br-virt,br-vmbr0";
static int garble_http_enabled = 0;
static int garble_udp_enabled = 0;
static int garble_tcp_aggressive = 0;
static int garble_tcp_avg_pkt = 0;
static int garble_tcp_repeat_pkt = 3;
static int garble_udp_repeat_pkt = 1;
static int garble_udp_aggressive = 0;
static int garble_udp_avg_pkt = 0;
static int garble_tcp_client_enabled = 0;
static int garble_local_obf_enabled = 0;
static int garble_wellknown_port_obf_enabled = 0;
static int garble_routing_enabled = 0;
static int garble_tcp_binary_payload = 0;
static int garble_udp_binary_payload = 0;
static int garble_udp_ttl = 3;                          // Default TTL value for UDP packets
static char garble_udp_obf_protos[UDP_OBF_PROTOS_BUF_LEN] = ""; // comma separated UDP obfuscation protos
static char garble_tcp_obf_protos[TCP_OBF_PROTOS_BUF_LEN] = ""; // comma separated TCP obfuscation protos
static int garble_tcp_ttl = 3;                          // Default TTL value for TCP packets
static int garble_ttl_percent = 0;                       // 0 disables dynamic TTL adjustment
static char garble_udp_extra[UDP_EXTRA_BUF_LEN] ={0};   // UDP extra configuration string

static struct garble_config __rcu *garble_cfg_ptr = NULL;
static struct garble_lan_config __rcu *garble_lan_cfg_ptr = NULL;
static struct garble_udp_obf_config __rcu *garble_udp_obf_cfg_ptr = NULL;
static struct garble_tcp_obf_config __rcu *garble_tcp_obf_cfg_ptr = NULL;

static DEFINE_SPINLOCK(garble_cfg_lock);
static DEFINE_SPINLOCK(garble_lan_cfg_lock);
static DEFINE_SPINLOCK(garble_udp_obf_cfg_lock);
static DEFINE_SPINLOCK(garble_tcp_obf_cfg_lock);
static LIST_HEAD(garble_udp_payload_files);
static LIST_HEAD(garble_tcp_payload_files);
static DEFINE_MUTEX(garble_udp_payload_files_lock);
static DEFINE_MUTEX(garble_tcp_payload_files_lock);

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
        kvfree(cfg);
}

static void garble_lan_config_free(struct rcu_head *head)
{
	struct garble_lan_config *cfg = container_of(head, struct garble_lan_config, rcu);
	kfree(cfg);
}

static void garble_udp_obf_config_free(struct rcu_head *head)
{
	struct garble_udp_obf_config *cfg =
		container_of(head, struct garble_udp_obf_config, rcu);

	kfree(cfg);
}

static void garble_tcp_obf_config_free(struct rcu_head *head)
{
	struct garble_tcp_obf_config *cfg =
		container_of(head, struct garble_tcp_obf_config, rcu);

	kfree(cfg);
}

#define GARBLE_OBF_PROTO_NAME_MAX 2

static const char * const garble_udp_obf_proto_names[][GARBLE_OBF_PROTO_NAME_MAX] = {
	[UDP_OBF_TURN_ALLOCATE] = { "turn_allocate", "turn" },
	[UDP_OBF_WECHAT_VIDEO] = { "wechat_video", "wechat" },
	[UDP_OBF_SIP_INVITE] = { "sip_invite", "sip" },
	[UDP_OBF_DTLS_CLIENTHELLO] = { "dtls_clienthello", "dtls" },
	[UDP_OBF_TURN_CREATE_PERMISSION] = { "turn_create_permission" },
	[UDP_OBF_TURN_ALLOCATE_ERROR_RESPONSE] = { "turn_allocate_error_response" },
	[UDP_OBF_TURN_CHANNEL_BIND] = { "turn_channel_bind" },
	[UDP_OBF_TFTP_RRQ] = { "tftp_rrq", "tftp" },
	[UDP_OBF_WECHAT_VIDEO_NEW] = { "wechat_video_new" },
	[UDP_OBF_XIAOMI_CAMERA] = { "xiaomi_camera", "xiaomi" },
	[UDP_OBF_BILIBILI_LIVE] = { "bilibili_live", "bilibili" },
	[UDP_OBF_PAYLOAD_FILE] = { "payload_file", "file" },
};

static const char * const garble_tcp_obf_proto_names[][GARBLE_OBF_PROTO_NAME_MAX] = {
	[TCP_OBF_HTTP] = { "http" },
	[TCP_OBF_TLS_CLIENTHELLO] = { "tls_clienthello", "tls" },
	[TCP_OBF_SSH_BANNER] = { "ssh_banner", "ssh" },
	[TCP_OBF_RTMP_HANDSHAKE] = { "rtmp_handshake", "rtmp" },
	[TCP_OBF_POSTGRES_STARTUP] = { "postgres_startup", "postgres" },
	[TCP_OBF_MQTT_CONNECT] = { "mqtt_connect", "mqtt" },
	[TCP_OBF_FTP_USER] = { "ftp_user", "ftp" },
	[TCP_OBF_PAYLOAD_FILE] = { "payload_file", "file" },
	[TCP_OBF_VNC] = { "vnc", "vnc" },
	[TCP_OBF_THRIFT] = { "thrift", "thrift_call" },
};

static const char *garble_obf_proto_name(
	const char * const names[][GARBLE_OBF_PROTO_NAME_MAX],
	int proto_max, int proto)
{
	if (proto < 0 || proto >= proto_max || !names[proto][0])
		return "unknown";

	return names[proto][0];
}

static int garble_obf_proto_from_token(
	const char * const names[][GARBLE_OBF_PROTO_NAME_MAX],
	int proto_max, const char *token)
{
	int proto;
	int i;

	for (proto = 0; proto < proto_max; proto++) {
		for (i = 0; i < GARBLE_OBF_PROTO_NAME_MAX; i++) {
			if (names[proto][i] && !strcmp(token, names[proto][i]))
				return proto;
		}
	}

	return -EINVAL;
}

inline const char *garble_get_udp_obf_proto_name(int proto)
{
	return garble_obf_proto_name(garble_udp_obf_proto_names,
				     UDP_OBF_PROTO_MAX, proto);
}

inline const char *garble_get_tcp_obf_proto_name(int proto)
{
	return garble_obf_proto_name(garble_tcp_obf_proto_names,
				     TCP_OBF_PROTO_MAX, proto);
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

static int proc_handler_ttl_percent(struct ctl_table *table, int write,
				    void __user *buffer, size_t *lenp,
				    loff_t *ppos)
{
	int ret;
	int new_percent;
	struct ctl_table tmp_table;

	if (!write)
		return proc_dointvec(table, write, buffer, lenp, ppos);

	memset(&tmp_table, 0, sizeof(tmp_table));
	tmp_table.data = &new_percent;
	tmp_table.maxlen = sizeof(int);

	ret = proc_dointvec(&tmp_table, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	if (new_percent < 0 || new_percent >= 100) {
		pr_info("garble: %s value %d is out of range [0, 99]\n",
			table->procname, new_percent);
		return -EINVAL;
	}

	*(int *)table->data = new_percent;
	pr_info("garble: %s updated to %d\n", table->procname, new_percent);

	return 0;
}

static int garble_udp_obf_proto_from_token(const char *token)
{
	int proto;

	proto = garble_obf_proto_from_token(garble_udp_obf_proto_names,
					    UDP_OBF_PROTO_MAX, token);
	if (proto >= 0)
		return proto;

	if (!kstrtoint(token, 0, &proto) && proto >= 0 &&
	    proto < UDP_OBF_PROTO_MAX)
		return proto;

	return -EINVAL;
}

static struct garble_udp_obf_config *garble_parse_udp_obf_protos(const char *src)
{
	struct garble_udp_obf_config *cfg;
	char *token;
	char *s;
	int proto;
	int weight;
	int explicit_weight = 0;
	int unspecified_count = 0;
	int unspecified_proto[UDP_OBF_PROTO_MAX];
	int remaining;
	int base_weight;
	int extra_weight;
	char *weight_str;

	if (!src)
		return NULL;

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg)
		return NULL;

	if (strscpy(cfg->proto_buf, src, sizeof(cfg->proto_buf)) < 0) {
		kfree(cfg);
		return NULL;
	}

	s = cfg->proto_buf;
	while ((token = strsep(&s, ",")) != NULL) {
		token = strim(token);
		if (*token == '\0')
			continue;

		weight_str = strchr(token, '=');
		if (weight_str) {
			*weight_str++ = '\0';
			token = strim(token);
			weight_str = strim(weight_str);
			if (*token == '\0' || *weight_str == '\0' ||
			    kstrtoint(weight_str, 0, &weight) ||
			    weight <= 0 || weight > 1000) {
				kfree(cfg);
				return NULL;
			}
		}

		proto = garble_udp_obf_proto_from_token(token);
		if (proto < 0) {
			kfree(cfg);
			return NULL;
		}
		if (cfg->mask & BIT(proto)) {
			kfree(cfg);
			return NULL;
		}

		cfg->mask |= BIT(proto);
		if (weight_str) {
			cfg->weights[proto] = weight;
			explicit_weight += weight;
			if (explicit_weight > 1000) {
				kfree(cfg);
				return NULL;
			}
		} else {
			unspecified_proto[unspecified_count++] = proto;
		}
	}

	if (!cfg->mask)
		return cfg;

	remaining = 1000 - explicit_weight;
	if (unspecified_count) {
		if (remaining <= 0) {
			kfree(cfg);
			return NULL;
		}

		base_weight = remaining / unspecified_count;
		extra_weight = remaining % unspecified_count;
		if (!base_weight) {
			kfree(cfg);
			return NULL;
		}

		for (proto = 0; proto < unspecified_count; proto++) {
			int unspecified = unspecified_proto[proto];

			cfg->weights[unspecified] = base_weight;
			if (extra_weight > 0) {
				cfg->weights[unspecified]++;
				extra_weight--;
			}
		}
	} else if (explicit_weight != 1000) {
		kfree(cfg);
		return NULL;
	}

	return cfg;
}

static void garble_format_udp_obf_proto_weights(char *buf, size_t size,
						struct garble_udp_obf_config *cfg)
{
	size_t pos = 0;
	int i;

	if (!size)
		return;

	if (!cfg || !cfg->mask) {
		scnprintf(buf, size, "(disabled)");
		return;
	}

	buf[0] = '\0';
	for (i = 0; i < UDP_OBF_PROTO_MAX; i++) {
		if (!(cfg->mask & BIT(i)))
			continue;

		pos += scnprintf(buf + pos, size - pos, "%s%s(%d)=%d",
				 pos ? "," : "",
				 garble_obf_proto_name(garble_udp_obf_proto_names,
						       UDP_OBF_PROTO_MAX, i),
				 i, cfg->weights[i]);
		if (pos >= size)
			break;
	}
}

static int proc_handler_udp_obf_proto(struct ctl_table *table, int write,
				    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	char tmp[UDP_OBF_PROTOS_BUF_LEN];
	char proto_list[256];
	struct garble_udp_obf_config *new_cfg;
	struct garble_udp_obf_config *old_cfg;
	struct ctl_table tmp_table;
	unsigned long flags;
	int ret;

	if (!write)
		return proc_dostring(table, write, buffer, lenp, ppos);

	strscpy(tmp, (char *)table->data, sizeof(tmp));
	tmp_table = *table;
	tmp_table.data = tmp;
	tmp_table.maxlen = sizeof(tmp);

	ret = proc_dostring(&tmp_table, write, buffer, lenp, ppos);
	if (ret != 0)
		return ret;

	new_cfg = garble_parse_udp_obf_protos(tmp);
	if (!new_cfg) {
		pr_info("garble: invalid udp_obf_proto value: %s\n", tmp);
		return -EINVAL;
	}

	strscpy((char *)table->data, tmp, table->maxlen);

	spin_lock_irqsave(&garble_udp_obf_cfg_lock, flags);
	old_cfg = rcu_dereference_protected(garble_udp_obf_cfg_ptr,
			lockdep_is_held(&garble_udp_obf_cfg_lock));
	rcu_assign_pointer(garble_udp_obf_cfg_ptr, new_cfg);
	spin_unlock_irqrestore(&garble_udp_obf_cfg_lock, flags);

	if (old_cfg)
		call_rcu(&old_cfg->rcu, garble_udp_obf_config_free);

	garble_format_udp_obf_proto_weights(proto_list, sizeof(proto_list),
					    new_cfg);
	pr_info("garble: udp_obf_proto updated to %s [%s]\n",
		new_cfg->mask ? tmp : "(disabled)", proto_list);

	return 0;
}

static int garble_tcp_obf_proto_from_token(const char *token)
{
	int proto;

	proto = garble_obf_proto_from_token(garble_tcp_obf_proto_names,
					    TCP_OBF_PROTO_MAX, token);
	if (proto >= 0)
		return proto;

	if (!kstrtoint(token, 0, &proto) && proto >= 0 &&
	    proto < TCP_OBF_PROTO_MAX)
		return proto;

	return -EINVAL;
}

static struct garble_tcp_obf_config *garble_parse_tcp_obf_protos(const char *src)
{
	char *s;
	char *token;
	struct garble_tcp_obf_config *cfg;
	int proto;
	int weight;
	int explicit_weight = 0;
	int unspecified_count = 0;
	int unspecified_proto[TCP_OBF_PROTO_MAX];
	int remaining;
	int base_weight;
	int extra_weight;
	char *weight_str;

	if (!src)
		return NULL;

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg)
		return NULL;

	if (strscpy(cfg->proto_buf, src, sizeof(cfg->proto_buf)) < 0) {
		kfree(cfg);
		return NULL;
	}

	s = cfg->proto_buf;
	while ((token = strsep(&s, ",")) != NULL) {
		token = strim(token);
		if (*token == '\0')
			continue;

		weight_str = strchr(token, '=');
		if (weight_str) {
			*weight_str++ = '\0';
			token = strim(token);
			weight_str = strim(weight_str);
			if (*token == '\0' || *weight_str == '\0' ||
			    kstrtoint(weight_str, 0, &weight) ||
			    weight <= 0 || weight > 1000) {
				kfree(cfg);
				return NULL;
			}
		}

		proto = garble_tcp_obf_proto_from_token(token);
		if (proto < 0) {
			kfree(cfg);
			return NULL;
		}
		if (cfg->mask & BIT(proto)) {
			kfree(cfg);
			return NULL;
		}

		cfg->mask |= BIT(proto);
		if (weight_str) {
			cfg->weights[proto] = weight;
			explicit_weight += weight;
			if (explicit_weight > 1000) {
				kfree(cfg);
				return NULL;
			}
		} else {
			unspecified_proto[unspecified_count++] = proto;
		}
	}

	if (!cfg->mask)
		return cfg;

	remaining = 1000 - explicit_weight;
	if (unspecified_count) {
		if (remaining <= 0) {
			kfree(cfg);
			return NULL;
		}

		base_weight = remaining / unspecified_count;
		extra_weight = remaining % unspecified_count;
		if (!base_weight) {
			kfree(cfg);
			return NULL;
		}

		for (proto = 0; proto < unspecified_count; proto++) {
			int unspecified = unspecified_proto[proto];

			cfg->weights[unspecified] = base_weight;
			if (extra_weight > 0) {
				cfg->weights[unspecified]++;
				extra_weight--;
			}
		}
	} else if (explicit_weight != 1000) {
		kfree(cfg);
		return NULL;
	}

	return cfg;
}

static void garble_format_tcp_obf_proto_weights(char *buf, size_t size,
						struct garble_tcp_obf_config *cfg)
{
	size_t pos = 0;
	int i;

	if (!size)
		return;

	if (!cfg || !cfg->mask) {
		scnprintf(buf, size, "(disabled)");
		return;
	}

	buf[0] = '\0';
	for (i = 0; i < TCP_OBF_PROTO_MAX; i++) {
		if (!(cfg->mask & BIT(i)))
			continue;

		pos += scnprintf(buf + pos, size - pos, "%s%s(%d)=%d",
				 pos ? "," : "",
				 garble_obf_proto_name(garble_tcp_obf_proto_names,
						       TCP_OBF_PROTO_MAX, i),
				 i, cfg->weights[i]);
		if (pos >= size)
			break;
	}
}

static int proc_handler_tcp_obf_protos(struct ctl_table *table, int write,
				    void __user *buffer, size_t *lenp, loff_t *ppos)
{
	char tmp[TCP_OBF_PROTOS_BUF_LEN];
	char proto_list[256];
	struct ctl_table tmp_table;
	struct garble_tcp_obf_config *new_cfg;
	struct garble_tcp_obf_config *old_cfg;
	unsigned long flags;
	int ret;

	if (!write)
		return proc_dostring(table, write, buffer, lenp, ppos);

	strscpy(tmp, (char *)table->data, sizeof(tmp));
	tmp_table = *table;
	tmp_table.data = tmp;
	tmp_table.maxlen = sizeof(tmp);

	ret = proc_dostring(&tmp_table, write, buffer, lenp, ppos);
	if (ret != 0)
		return ret;

	new_cfg = garble_parse_tcp_obf_protos(tmp);
	if (!new_cfg) {
		pr_info("garble: invalid tcp_obf_proto value: %s\n",
			tmp);
		return -EINVAL;
	}

	strscpy((char *)table->data, tmp, table->maxlen);

	spin_lock_irqsave(&garble_tcp_obf_cfg_lock, flags);
	old_cfg = rcu_dereference_protected(garble_tcp_obf_cfg_ptr,
			lockdep_is_held(&garble_tcp_obf_cfg_lock));
	rcu_assign_pointer(garble_tcp_obf_cfg_ptr, new_cfg);
	spin_unlock_irqrestore(&garble_tcp_obf_cfg_lock, flags);

	if (old_cfg)
		call_rcu(&old_cfg->rcu, garble_tcp_obf_config_free);

	garble_format_tcp_obf_proto_weights(proto_list, sizeof(proto_list),
					    new_cfg);
	pr_info("garble: tcp_obf_proto updated to %s [%s]\n",
		new_cfg->mask ? tmp : "(disabled)", proto_list);

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

	new_cfg = kvzalloc(sizeof(*new_cfg), GFP_KERNEL);
	if (NULL == new_cfg)
		return -ENOMEM;

	/*
	 * strscpy确保domain_buf字符串以'\0'结束（其实kzalloc已经确保了最后一个字节必定为'\0'）
	 */
	if (strscpy(new_cfg->domain_buf, (char *)table->data, DOMAINS_BUF_LEN) < 0) {
		kvfree(new_cfg);
		return -EINVAL;
	}

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

static void garble_payload_blob_free(struct garble_payload_blob *blob)
{
	if (blob)
		kfree_rcu(blob, rcu);
}

static void garble_payload_file_put(struct garble_payload_file *payload_file)
{
	if (refcount_dec_and_test(&payload_file->refcnt)) {
		garble_payload_blob_free(
			rcu_dereference_protected(payload_file->blob, true));
		kfree_rcu(payload_file, rcu);
	}
}

static int garble_payload_file_open(struct inode *inode, struct file *file)
{
	struct garble_payload_file *payload_file = PDE_DATA(inode);
	int ret = 0;

	mutex_lock(&garble_udp_payload_files_lock);
	if (!payload_file || payload_file->removed) {
		ret = -ENOENT;
	} else {
		refcount_inc(&payload_file->refcnt);
		file->private_data = payload_file;
	}
	mutex_unlock(&garble_udp_payload_files_lock);

	return ret;
}

static int garble_payload_file_release(struct inode *inode, struct file *file)
{
	struct garble_payload_file *payload_file = file->private_data;

	if (payload_file)
		garble_payload_file_put(payload_file);

	return 0;
}

static ssize_t garble_payload_file_read(struct file *file, char __user *buf,
					size_t count, loff_t *ppos)
{
	struct garble_payload_file *payload_file = file->private_data;
	struct garble_payload_blob *blob;
	char data[GARBLE_MAX_UDP_PAYLOAD];
	int data_len;

	if (!payload_file)
		return -ENOENT;

	rcu_read_lock();
	blob = rcu_dereference(payload_file->blob);
	if (!blob) {
		rcu_read_unlock();
		return 0;
	}

	data_len = blob->len;
	if (*ppos >= data_len) {
		rcu_read_unlock();
		return 0;
	}

	if (count > data_len - *ppos)
		count = data_len - *ppos;

	memcpy(data, blob->data + *ppos, count);
	rcu_read_unlock();

	if (copy_to_user(buf, data, count))
		return -EFAULT;

	*ppos += count;
	return count;
}

static ssize_t garble_payload_file_write(struct file *file,
					 const char __user *buf,
					 size_t count, loff_t *ppos)
{
	struct garble_payload_file *payload_file = file->private_data;
	struct garble_payload_blob *blob;
	struct garble_payload_blob *old_blob;
	char data[GARBLE_MAX_UDP_PAYLOAD];

	if (!payload_file)
		return -ENOENT;

	if (count > payload_file->max_len)
		return -EFBIG;

	if (copy_from_user(data, buf, count))
		return -EFAULT;

	blob = kzalloc(sizeof(*blob), GFP_KERNEL);
	if (!blob)
		return -ENOMEM;

	memcpy(blob->data, data, count);
	blob->len = count;

	spin_lock(&payload_file->update_lock);
	old_blob = rcu_replace_pointer(payload_file->blob, blob, true);
	spin_unlock(&payload_file->update_lock);
	*ppos = count;
	garble_payload_blob_free(old_blob);

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops payload_file_proc_ops = {
	.proc_open	= garble_payload_file_open,
	.proc_read	= garble_payload_file_read,
	.proc_write	= garble_payload_file_write,
	.proc_release	= garble_payload_file_release,
};
#else
static const struct file_operations payload_file_proc_ops = {
	.owner		= THIS_MODULE,
	.open		= garble_payload_file_open,
	.read		= garble_payload_file_read,
	.write		= garble_payload_file_write,
	.release	= garble_payload_file_release,
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
		.procname	= "udp_repeat_pkt",
		.data		= &garble_udp_repeat_pkt,
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
		.procname	= "ttl_percent",
		.data		= &garble_ttl_percent,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_handler_ttl_percent,
	},
	{
		.procname	= "udp_obf_proto",
		.data		= garble_udp_obf_protos,
		.maxlen		= UDP_OBF_PROTOS_BUF_LEN,
		.mode		= 0644,
		.proc_handler	= proc_handler_udp_obf_proto,
	},
	{
		.procname	= "tcp_obf_proto",
		.data		= garble_tcp_obf_protos,
		.maxlen		= TCP_OBF_PROTOS_BUF_LEN,
		.mode		= 0644,
		.proc_handler	= proc_handler_tcp_obf_protos,
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
static struct proc_dir_entry *protos_proc_entry;
static struct proc_dir_entry *udp_proc_dir;
static struct proc_dir_entry *tcp_proc_dir;
static struct proc_dir_entry *udp_payload_file_proc_dir;
static struct proc_dir_entry *tcp_payload_file_proc_dir;
static struct proc_dir_entry *udp_payload_file_ctl_proc_entry;
static struct proc_dir_entry *tcp_payload_file_ctl_proc_entry;

struct garble_payload_file_set {
	struct list_head *files;
	struct mutex *lock;
	struct proc_dir_entry *dir;
	int max_len;
};

static struct garble_payload_file_set garble_udp_payload_file_set = {
	.files = &garble_udp_payload_files,
	.lock = &garble_udp_payload_files_lock,
	.max_len = GARBLE_MAX_UDP_PAYLOAD,
};

static struct garble_payload_file_set garble_tcp_payload_file_set = {
	.files = &garble_tcp_payload_files,
	.lock = &garble_tcp_payload_files_lock,
	.max_len = GARBLE_MAX_TCP_PAYLOAD,
};

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

static void garble_protos_seq_print_names(struct seq_file *m,
					  const char * const names[][GARBLE_OBF_PROTO_NAME_MAX],
					  int proto)
{
	int i;
	bool printed = false;

	for (i = 0; i < GARBLE_OBF_PROTO_NAME_MAX; i++) {
		if (!names[proto][i])
			continue;

		seq_printf(m, "%s%s", printed ? "/" : "", names[proto][i]);
		printed = true;
	}
}

static int garble_protos_show(struct seq_file *m, void *v)
{
	int i;

	seq_puts(m, "tcp:\n");
	for (i = 0; i < TCP_OBF_PROTO_MAX; i++) {
		seq_printf(m, "  %d ", i);
		garble_protos_seq_print_names(m, garble_tcp_obf_proto_names, i);
		seq_putc(m, '\n');
	}

	seq_puts(m, "udp:\n");
	for (i = 0; i < UDP_OBF_PROTO_MAX; i++) {
		seq_printf(m, "  %d ", i);
		garble_protos_seq_print_names(m, garble_udp_obf_proto_names, i);
		seq_putc(m, '\n');
	}

	return 0;
}

static int garble_protos_open(struct inode *inode, struct file *file)
{
	return single_open(file, garble_protos_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops garble_stats_proc_ops = {
	.proc_read	= garble_stats_read,
};

static const struct proc_ops garble_protos_proc_ops = {
	.proc_open	= garble_protos_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#else
static const struct file_operations garble_stats_proc_ops = {
	.owner		= THIS_MODULE,
	.read		= garble_stats_read,
};

static const struct file_operations garble_protos_proc_ops = {
	.owner		= THIS_MODULE,
	.open		= garble_protos_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

static int garble_payload_file_name_valid(const char *name)
{
	if (!name || !name[0] || strlen(name) >= GARBLE_PAYLOAD_FILE_NAME_LEN)
		return 0;

	if (!strcmp(name, ".") || !strcmp(name, "..") || !strcmp(name, "ctl"))
		return 0;

	return !strchr(name, '/') && !strchr(name, ' ') && !strchr(name, '\t');
}

static struct garble_payload_file *garble_payload_file_find(
	struct garble_payload_file_set *set, const char *name)
{
	struct garble_payload_file *payload_file;

	list_for_each_entry(payload_file, set->files, list) {
		if (!strcmp(payload_file->name, name))
			return payload_file;
	}

	return NULL;
}

static int garble_payload_file_create(struct garble_payload_file_set *set,
				      const char *name)
{
	struct garble_payload_file *payload_file;
	struct proc_dir_entry *entry;

	if (!garble_payload_file_name_valid(name))
		return -EINVAL;

	mutex_lock(set->lock);
	if (garble_payload_file_find(set, name)) {
		mutex_unlock(set->lock);
		return -EEXIST;
	}
	mutex_unlock(set->lock);

	payload_file = kzalloc(sizeof(*payload_file), GFP_KERNEL);
	if (!payload_file)
		return -ENOMEM;

	strscpy(payload_file->name, name, sizeof(payload_file->name));
	spin_lock_init(&payload_file->update_lock);
	refcount_set(&payload_file->refcnt, 1);
	payload_file->max_len = set->max_len;

	entry = proc_create_data(payload_file->name, 0644,
				 set->dir,
				 &payload_file_proc_ops,
				 payload_file);
	if (!entry) {
		kfree(payload_file);
		return -ENOMEM;
	}

	payload_file->entry = entry;

	mutex_lock(set->lock);
	if (garble_payload_file_find(set, payload_file->name)) {
		mutex_unlock(set->lock);
		proc_remove(entry);
		kfree(payload_file);
		return -EEXIST;
	}
	list_add_tail_rcu(&payload_file->list, set->files);
	mutex_unlock(set->lock);

	return 0;
}

static int garble_payload_file_delete(struct garble_payload_file_set *set,
				      const char *name)
{
	struct garble_payload_file *payload_file;

	if (!garble_payload_file_name_valid(name))
		return -EINVAL;

	mutex_lock(set->lock);
	payload_file = garble_payload_file_find(set, name);
	if (!payload_file) {
		mutex_unlock(set->lock);
		return -ENOENT;
	}

	list_del_rcu(&payload_file->list);
	WRITE_ONCE(payload_file->removed, true);
	mutex_unlock(set->lock);

	proc_remove(payload_file->entry);
	garble_payload_file_put(payload_file);

	return 0;
}

static void garble_payload_files_remove_all(struct garble_payload_file_set *set)
{
	struct garble_payload_file *payload_file;

	mutex_lock(set->lock);
	while (!list_empty(set->files)) {
		payload_file = list_first_entry(set->files,
						struct garble_payload_file,
						list);
		list_del_rcu(&payload_file->list);
		WRITE_ONCE(payload_file->removed, true);
		mutex_unlock(set->lock);

		proc_remove(payload_file->entry);
		garble_payload_file_put(payload_file);

		mutex_lock(set->lock);
	}
	mutex_unlock(set->lock);
}

static ssize_t payload_file_ctl_read(struct file *file, char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct garble_payload_file_set *set = PDE_DATA(file_inode(file));
	struct garble_payload_file *payload_file;
	char out[512];
	size_t pos = 0;

	mutex_lock(set->lock);
	list_for_each_entry(payload_file, set->files, list) {
		struct garble_payload_blob *blob;
		int len = 0;

		rcu_read_lock();
		blob = rcu_dereference(payload_file->blob);
		if (blob)
			len = blob->len;
		rcu_read_unlock();

		pos += scnprintf(out + pos, sizeof(out) - pos, "%s %d\n",
				 payload_file->name, len);
		if (pos >= sizeof(out))
			break;
	}
	mutex_unlock(set->lock);

	return simple_read_from_buffer(buf, count, ppos, out, pos);
}

static ssize_t payload_file_ctl_write(struct file *file,
				      const char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct garble_payload_file_set *set = PDE_DATA(file_inode(file));
	char cmd[GARBLE_PAYLOAD_FILE_CTL_BUF_LEN];
	char *op;
	char *name;
	int ret;

	if (count >= sizeof(cmd))
		return -EFBIG;

	if (copy_from_user(cmd, buf, count))
		return -EFAULT;

	cmd[count] = '\0';
	strim(cmd);
	op = strim(cmd);
	name = strpbrk(op, " \t");
	if (!name)
		return -EINVAL;
	*name++ = '\0';
	name = strim(name);

	if (!strcmp(op, "create"))
		ret = garble_payload_file_create(set, name);
	else if (!strcmp(op, "delete") || !strcmp(op, "remove"))
		ret = garble_payload_file_delete(set, name);
	else
		ret = -EINVAL;

	return ret ? ret : count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops payload_file_ctl_proc_ops = {
	.proc_read	= payload_file_ctl_read,
	.proc_write	= payload_file_ctl_write,
};
#else
static const struct file_operations payload_file_ctl_proc_ops = {
	.owner		= THIS_MODULE,
	.read		= payload_file_ctl_read,
	.write		= payload_file_ctl_write,
};
#endif

int garble_sysctl_init(void)
{
	struct garble_lan_config *default_lan_cfg;
	struct garble_udp_obf_config *default_udp_obf_cfg;
	struct garble_tcp_obf_config *default_tcp_obf_cfg;
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

	protos_proc_entry = proc_create("protos", 0444, garble_proc_dir,
				       &garble_protos_proc_ops);
	if (!protos_proc_entry) {
		pr_err("garble: failed to create /proc/garble/protos entry\n");
		remove_proc_entry("stats", garble_proc_dir);
		remove_proc_entry("tcp_payload", garble_proc_dir);
		remove_proc_entry("udp_payload", garble_proc_dir);
		remove_proc_entry("garble", NULL);
		return -ENOMEM;
	}

	udp_proc_dir = proc_mkdir("udp", garble_proc_dir);
	if (!udp_proc_dir) {
		pr_err("garble: failed to create /proc/garble/udp directory\n");
		remove_proc_entry("protos", garble_proc_dir);
		remove_proc_entry("stats", garble_proc_dir);
		remove_proc_entry("tcp_payload", garble_proc_dir);
		remove_proc_entry("udp_payload", garble_proc_dir);
		remove_proc_entry("garble", NULL);
		return -ENOMEM;
	}

	udp_payload_file_proc_dir = proc_mkdir("payload_file", udp_proc_dir);
	if (!udp_payload_file_proc_dir) {
		pr_err("garble: failed to create /proc/garble/udp/payload_file directory\n");
		remove_proc_entry("udp", garble_proc_dir);
		remove_proc_entry("protos", garble_proc_dir);
		remove_proc_entry("stats", garble_proc_dir);
		remove_proc_entry("tcp_payload", garble_proc_dir);
		remove_proc_entry("udp_payload", garble_proc_dir);
		remove_proc_entry("garble", NULL);
		return -ENOMEM;
	}
	garble_udp_payload_file_set.dir = udp_payload_file_proc_dir;

	udp_payload_file_ctl_proc_entry = proc_create_data("ctl", 0644,
					udp_payload_file_proc_dir,
					&payload_file_ctl_proc_ops,
					&garble_udp_payload_file_set);
	if (!udp_payload_file_ctl_proc_entry) {
		pr_err("garble: failed to create /proc/garble/udp/payload_file/ctl entry\n");
		remove_proc_entry("payload_file", udp_proc_dir);
		remove_proc_entry("udp", garble_proc_dir);
		remove_proc_entry("protos", garble_proc_dir);
		remove_proc_entry("stats", garble_proc_dir);
		remove_proc_entry("tcp_payload", garble_proc_dir);
		remove_proc_entry("udp_payload", garble_proc_dir);
		remove_proc_entry("garble", NULL);
		return -ENOMEM;
	}

	tcp_proc_dir = proc_mkdir("tcp", garble_proc_dir);
	if (!tcp_proc_dir) {
		pr_err("garble: failed to create /proc/garble/tcp directory\n");
		remove_proc_entry("ctl", udp_payload_file_proc_dir);
		remove_proc_entry("payload_file", udp_proc_dir);
		remove_proc_entry("udp", garble_proc_dir);
		remove_proc_entry("protos", garble_proc_dir);
		remove_proc_entry("stats", garble_proc_dir);
		remove_proc_entry("tcp_payload", garble_proc_dir);
		remove_proc_entry("udp_payload", garble_proc_dir);
		remove_proc_entry("garble", NULL);
		return -ENOMEM;
	}

	tcp_payload_file_proc_dir = proc_mkdir("payload_file", tcp_proc_dir);
	if (!tcp_payload_file_proc_dir) {
		pr_err("garble: failed to create /proc/garble/tcp/payload_file directory\n");
		remove_proc_entry("tcp", garble_proc_dir);
		remove_proc_entry("ctl", udp_payload_file_proc_dir);
		remove_proc_entry("payload_file", udp_proc_dir);
		remove_proc_entry("udp", garble_proc_dir);
		remove_proc_entry("protos", garble_proc_dir);
		remove_proc_entry("stats", garble_proc_dir);
		remove_proc_entry("tcp_payload", garble_proc_dir);
		remove_proc_entry("udp_payload", garble_proc_dir);
		remove_proc_entry("garble", NULL);
		return -ENOMEM;
	}
	garble_tcp_payload_file_set.dir = tcp_payload_file_proc_dir;

	tcp_payload_file_ctl_proc_entry = proc_create_data("ctl", 0644,
					tcp_payload_file_proc_dir,
					&payload_file_ctl_proc_ops,
					&garble_tcp_payload_file_set);
	if (!tcp_payload_file_ctl_proc_entry) {
		pr_err("garble: failed to create /proc/garble/tcp/payload_file/ctl entry\n");
		remove_proc_entry("payload_file", tcp_proc_dir);
		remove_proc_entry("tcp", garble_proc_dir);
		remove_proc_entry("ctl", udp_payload_file_proc_dir);
		remove_proc_entry("payload_file", udp_proc_dir);
		remove_proc_entry("udp", garble_proc_dir);
		remove_proc_entry("protos", garble_proc_dir);
		remove_proc_entry("stats", garble_proc_dir);
		remove_proc_entry("tcp_payload", garble_proc_dir);
		remove_proc_entry("udp_payload", garble_proc_dir);
		remove_proc_entry("garble", NULL);
		return -ENOMEM;
	}

	default_lan_cfg = garble_parse_lan_nics(garble_lan_args);
	if (!default_lan_cfg)
		return -ENOMEM;

	default_udp_obf_cfg = garble_parse_udp_obf_protos(garble_udp_obf_protos);
	if (!default_udp_obf_cfg) {
		kfree(default_lan_cfg);
		return -ENOMEM;
	}

	default_tcp_obf_cfg = garble_parse_tcp_obf_protos(garble_tcp_obf_protos);
	if (!default_tcp_obf_cfg) {
		kfree(default_lan_cfg);
		kfree(default_udp_obf_cfg);
		return -ENOMEM;
	}

	spin_lock_irqsave(&garble_lan_cfg_lock, flags);
	rcu_assign_pointer(garble_lan_cfg_ptr, default_lan_cfg);
	spin_unlock_irqrestore(&garble_lan_cfg_lock, flags);

	spin_lock_irqsave(&garble_udp_obf_cfg_lock, flags);
	rcu_assign_pointer(garble_udp_obf_cfg_ptr, default_udp_obf_cfg);
	spin_unlock_irqrestore(&garble_udp_obf_cfg_lock, flags);

	spin_lock_irqsave(&garble_tcp_obf_cfg_lock, flags);
	rcu_assign_pointer(garble_tcp_obf_cfg_ptr, default_tcp_obf_cfg);
	spin_unlock_irqrestore(&garble_tcp_obf_cfg_lock, flags);

        return 0;
}

void garble_sysctl_exit(void)
{
	struct garble_config *cfg;
	struct garble_lan_config *lan_cfg;
	struct garble_udp_obf_config *udp_obf_cfg;
	struct garble_tcp_obf_config *tcp_obf_cfg;
	unsigned long flags;

	unregister_sysctl_table(garble_sysctl_header);

	/* Remove procfs entries */
	garble_payload_files_remove_all(&garble_udp_payload_file_set);
	garble_payload_files_remove_all(&garble_tcp_payload_file_set);
	if (tcp_payload_file_ctl_proc_entry)
		remove_proc_entry("ctl", tcp_payload_file_proc_dir);
	if (tcp_payload_file_proc_dir)
		remove_proc_entry("payload_file", tcp_proc_dir);
	if (tcp_proc_dir)
		remove_proc_entry("tcp", garble_proc_dir);
	if (udp_payload_file_ctl_proc_entry)
		remove_proc_entry("ctl", udp_payload_file_proc_dir);
	if (udp_payload_file_proc_dir)
		remove_proc_entry("payload_file", udp_proc_dir);
	if (udp_proc_dir)
		remove_proc_entry("udp", garble_proc_dir);
	if (protos_proc_entry)
		remove_proc_entry("protos", garble_proc_dir);
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

	spin_lock_irqsave(&garble_udp_obf_cfg_lock, flags);
	udp_obf_cfg = rcu_dereference_protected(garble_udp_obf_cfg_ptr,
					    lockdep_is_held(&garble_udp_obf_cfg_lock));
	rcu_assign_pointer(garble_udp_obf_cfg_ptr, NULL);
	spin_unlock_irqrestore(&garble_udp_obf_cfg_lock, flags);

	if (udp_obf_cfg)
		call_rcu(&udp_obf_cfg->rcu, garble_udp_obf_config_free);

	spin_lock_irqsave(&garble_tcp_obf_cfg_lock, flags);
	tcp_obf_cfg = rcu_dereference_protected(garble_tcp_obf_cfg_ptr,
					    lockdep_is_held(&garble_tcp_obf_cfg_lock));
	rcu_assign_pointer(garble_tcp_obf_cfg_ptr, NULL);
	spin_unlock_irqrestore(&garble_tcp_obf_cfg_lock, flags);

	if (tcp_obf_cfg)
		call_rcu(&tcp_obf_cfg->rcu, garble_tcp_obf_config_free);
}

inline bool garble_check_if_tcp_enabled(void)
{
	return garble_enabled || garble_http_enabled ||
	       garble_check_if_tcp_obf_enabled() ||
	       garble_tcp_binary_payload;
}

inline bool garble_check_if_tcp_aggressive(void)
{
	return garble_tcp_aggressive;
}

inline bool garble_check_if_tcp_double_enabled(void)
{
	return garble_enabled && garble_http_enabled;
}

inline bool garble_check_if_tcp_obf_enabled(void)
{
	struct garble_tcp_obf_config *cfg;
	bool enabled;

	rcu_read_lock();
	cfg = rcu_dereference(garble_tcp_obf_cfg_ptr);
	enabled = cfg && cfg->mask;
	rcu_read_unlock();

	return enabled;
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
	return !garble_enabled && !garble_http_enabled &&
	       !garble_check_if_tcp_obf_enabled() &&
	       !garble_tcp_binary_payload;
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

inline int garble_get_udp_repeat_pkt(void)
{
	return garble_udp_repeat_pkt;
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

inline int garble_estimate_hops(u8 ttl)
{
	/*
	 * Estimate hop count from the observed TTL/hop-limit.
	 * assume the peer started from one of the common initial TTL values
	 * 64, 128 or 255, then subtract the remaining TTL we saw.
	 */
	if (ttl <= 64)
		return 64 - ttl;
	else if (ttl <= 128)
		return 128 - ttl;

	return 255 - ttl;
}

inline int garble_calc_ttl(int base_ttl, u8 src_ttl)
{
	int ttl;
	int hops;

	if (!garble_ttl_percent || !src_ttl)
		return base_ttl;

	hops = garble_estimate_hops(src_ttl);
	ttl = hops * garble_ttl_percent / 100;

	return ttl > base_ttl ? ttl : base_ttl;
}

inline int garble_calc_tcp_ttl(u8 src_ttl)
{
	return garble_calc_ttl(garble_tcp_ttl, src_ttl);
}

inline int garble_calc_udp_ttl(u8 src_ttl)
{
	return garble_calc_ttl(garble_udp_ttl, src_ttl);
}

inline int garble_get_udp_obf_proto(void)
{
	struct garble_udp_obf_config *cfg;
	int total_weight = 0;
	int target;
	int i;

	rcu_read_lock();
	cfg = rcu_dereference(garble_udp_obf_cfg_ptr);
	if (!cfg || !cfg->mask) {
		rcu_read_unlock();
		return UDP_OBF_PROTO_MAX;
	}

	for (i = 0; i < UDP_OBF_PROTO_MAX; i++) {
		if (cfg->mask & BIT(i))
			total_weight += cfg->weights[i];
	}

	if (total_weight <= 0) {
		rcu_read_unlock();
		return UDP_OBF_PROTO_MAX;
	}

	target = prandom_u32() % total_weight;
	for (i = 0; i < UDP_OBF_PROTO_MAX; i++) {
		if (!(cfg->mask & BIT(i)))
			continue;
		if (target < cfg->weights[i]) {
			rcu_read_unlock();
			return i;
		}
		target -= cfg->weights[i];
	}

	rcu_read_unlock();
	return UDP_OBF_PROTO_MAX;
}

inline int garble_get_tcp_obf_proto(void)
{
	struct garble_tcp_obf_config *cfg;
	int total_weight = 0;
	int target;
	int i;

	rcu_read_lock();
	cfg = rcu_dereference(garble_tcp_obf_cfg_ptr);
	if (!cfg || !cfg->mask) {
		rcu_read_unlock();
		return TCP_OBF_TLS_CLIENTHELLO;
	}

	for (i = 0; i < TCP_OBF_PROTO_MAX; i++) {
		if (cfg->mask & BIT(i))
			total_weight += cfg->weights[i];
	}

	if (total_weight <= 0) {
		rcu_read_unlock();
		return TCP_OBF_TLS_CLIENTHELLO;
	}

	target = prandom_u32() % total_weight;
	for (i = 0; i < TCP_OBF_PROTO_MAX; i++) {
		if (!(cfg->mask & BIT(i)))
			continue;
		if (target < cfg->weights[i]) {
			rcu_read_unlock();
			return i;
		}
		target -= cfg->weights[i];
	}

	rcu_read_unlock();
	return TCP_OBF_TLS_CLIENTHELLO;
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

static unsigned char *garble_get_payload_file(struct garble_payload_file_set *set,
					      unsigned char *buf, int *len)
{
	struct garble_payload_file *payload_file;
	struct garble_payload_blob *blob;
	int count = 0;
	int target;

	rcu_read_lock();
	list_for_each_entry_rcu(payload_file, set->files, list) {
		if (READ_ONCE(payload_file->removed))
			continue;

		blob = rcu_dereference(payload_file->blob);
		if (blob && blob->len > 0)
			count++;
	}

	if (!count) {
		rcu_read_unlock();
		*len = 0;
		return NULL;
	}

	target = prandom_u32() % count;
	list_for_each_entry_rcu(payload_file, set->files, list) {
		if (READ_ONCE(payload_file->removed))
			continue;

		blob = rcu_dereference(payload_file->blob);
		if (!blob || blob->len <= 0)
			continue;
		if (target-- == 0) {
			*len = blob->len;
			memcpy(buf, blob->data, blob->len);
			rcu_read_unlock();
			return buf;
		}
	}
	rcu_read_unlock();

	*len = 0;
	return NULL;
}

inline unsigned char *garble_get_udp_payload_file(unsigned char *buf, int *len)
{
	return garble_get_payload_file(&garble_udp_payload_file_set, buf, len);
}

inline unsigned char *garble_get_tcp_payload_file(unsigned char *buf, int *len)
{
	return garble_get_payload_file(&garble_tcp_payload_file_set, buf, len);
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
