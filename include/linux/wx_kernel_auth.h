/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_WX_KERNEL_AUTH_H
#define _LINUX_WX_KERNEL_AUTH_H

#include <uapi/linux/wx_kernel_auth.h>

int wx_kernel_auth_challenge(const struct wx_kernel_auth_req *req,
			     struct wx_kernel_auth_resp *resp);

#endif /* _LINUX_WX_KERNEL_AUTH_H */
