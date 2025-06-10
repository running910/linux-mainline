#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>

#define DOMAINS_BUF_LEN 512
#define MAX_DOMAINS     20

static int garble_enabled = 0;
static char garble_domains[DOMAINS_BUF_LEN] = "";
static char garble_args[DOMAINS_BUF_LEN] = "";
static char *domain_list[MAX_DOMAINS] = {0}; 
static int num_domains = 0;

static int proc_handler_domains(struct ctl_table *table, int write,
                      void __user *buffer, size_t *lenp, loff_t *ppos)
{
        int i;

        int ret = proc_dostring(table, write, buffer, lenp, ppos);
        if (ret != 0 || !write)
                return ret;

        memcpy(garble_domains, garble_args, sizeof(garble_domains));

        num_domains = 0;
        char *s = garble_domains;
        char *token;

        while ((token = strsep(&s, ",")) != NULL && num_domains < MAX_DOMAINS) {
                domain_list[num_domains++] = token;
        }

        printk(KERN_INFO "Parsed %d domains\n", num_domains);
        for (i = 0; i < num_domains; ++i)
                printk(KERN_INFO "Domain[%d] = %s\n", i, domain_list[i]);

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
                __log("register_sysctl_table() success!");
        } else {
                __log("register_sysctl_table() failed!");
        }

        return 0;
}