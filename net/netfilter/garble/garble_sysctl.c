#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>

#define DOMAINS_BUF_LEN 512

static int garble_enabled = 0;
static char garble_domains[DOMAINS_BUF_LEN] = "";

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
                .data       = garble_domains,
                .maxlen     = DOMAINS_BUF_LEN,
                .mode       = 0644,
                .proc_handler = proc_dostring,
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