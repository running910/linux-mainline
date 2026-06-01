/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_WX_KERNEL_ATTEST_H
#define _LINUX_WX_KERNEL_ATTEST_H

#include <uapi/linux/wx_kernel_attest.h>

int wx_kernel_attest_challenge(const struct wx_kernel_attest_req *req,
			       struct wx_kernel_attest_resp *resp);

#endif /* _LINUX_WX_KERNEL_ATTEST_H */
