// SPDX-License-Identifier: GPL-2.0
#include <linux/ktime.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/wx_kernel_auth.h>

static u8 wx_kernel_auth_boot_id[WX_KERNEL_AUTH_BOOT_ID_SIZE];
static DEFINE_MUTEX(wx_kernel_auth_lock);

static void wx_kernel_auth_init_boot_id(void)
{
	static bool initialized;

	if (likely(READ_ONCE(initialized)))
		return;

	mutex_lock(&wx_kernel_auth_lock);
	if (!initialized) {
		get_random_bytes(wx_kernel_auth_boot_id,
				 sizeof(wx_kernel_auth_boot_id));
		WRITE_ONCE(initialized, true);
	}
	mutex_unlock(&wx_kernel_auth_lock);
}

int wx_kernel_auth_challenge(const struct wx_kernel_auth_req *req,
			     struct wx_kernel_auth_resp *resp)
{
	if (!req || !resp)
		return -EINVAL;

	if (req->magic != WX_KERNEL_AUTH_MAGIC ||
	    req->version != WX_KERNEL_AUTH_VERSION ||
	    req->size < sizeof(*req) ||
	    req->cmd != WX_KERNEL_AUTH_CHALLENGE)
		return -EINVAL;

	wx_kernel_auth_init_boot_id();

	memset(resp, 0, sizeof(*resp));
	resp->magic = WX_KERNEL_AUTH_MAGIC;
	resp->version = WX_KERNEL_AUTH_VERSION;
	resp->size = sizeof(*resp);
	memcpy(resp->nonce, req->nonce, sizeof(resp->nonce));
	memcpy(resp->boot_id, wx_kernel_auth_boot_id,
	       sizeof(resp->boot_id));
	resp->ktime_ns = ktime_get_ns();

	return 0;
}
EXPORT_SYMBOL_GPL(wx_kernel_auth_challenge);

SYSCALL_DEFINE3(wx_kernel_auth, unsigned int, cmd,
		struct wx_kernel_auth_req __user *, ureq,
		struct wx_kernel_auth_resp __user *, uresp)
{
	struct wx_kernel_auth_req req;
	struct wx_kernel_auth_resp resp;
	int ret;

	if (cmd != WX_KERNEL_AUTH_CHALLENGE)
		return -EINVAL;

	if (copy_from_user(&req, ureq, sizeof(req)))
		return -EFAULT;

	ret = wx_kernel_auth_challenge(&req, &resp);
	if (ret)
		return ret;

	if (copy_to_user(uresp, &resp, sizeof(resp)))
		return -EFAULT;

	return 0;
}
