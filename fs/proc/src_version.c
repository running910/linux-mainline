// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

extern const char linux_src_banner[];

static int src_version_proc_show(struct seq_file *m, void *v)
{
	seq_puts(m, linux_src_banner);
	return 0;
}

static int __init proc_src_version_init(void)
{
	proc_create_single("src_version", 0, NULL, src_version_proc_show);
	return 0;
}
fs_initcall(proc_src_version_init);
