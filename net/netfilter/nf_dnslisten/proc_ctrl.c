#include <linux/sysctl.h>
#include <net/net_namespace.h>

#include "common.h"


extern int nf_dnslisten_enable;
extern int nf_dnslisten_mod;


static struct ctl_table_header *nf_dnslisten_ctl_header = NULL;

static struct ctl_table nf_dnslisten_ctl_table[] = {
	{
		.procname	= "nf_dnslisten",
		.data		= &nf_dnslisten_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "nf_dnslisten_mod",
		.data		= &nf_dnslisten_mod,
		.maxlen 	= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

int proc_ctrl_init(void)
{
	nf_dnslisten_ctl_header = register_net_sysctl(&init_net, "net/netfilter", nf_dnslisten_ctl_table);
	if (!nf_dnslisten_ctl_header) {
		__log("dnslisten register_net_sysctl failed!");	
		return -1;
	}

	return 0;
}

int proc_ctrl_exit(void)
{
	if (nf_dnslisten_ctl_header) {
		unregister_net_sysctl_table(nf_dnslisten_ctl_header);
	}

	return 0;
}
