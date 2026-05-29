/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_WX_KERNEL_AUTH_H
#define _UAPI_LINUX_WX_KERNEL_AUTH_H

#include <linux/types.h>

#define WX_KERNEL_AUTH_MAGIC		0x57584154 /* "WXAT" */
#define WX_KERNEL_AUTH_VERSION		1
#define WX_KERNEL_AUTH_CHALLENGE	1

#define WX_KERNEL_AUTH_NONCE_SIZE	32
#define WX_KERNEL_AUTH_BOOT_ID_SIZE	16

struct wx_kernel_auth_req {
	__u32 magic;
	__u16 version;
	__u16 flags;
	__u32 size;
	__u32 cmd;
	__u8 nonce[WX_KERNEL_AUTH_NONCE_SIZE];
};

struct wx_kernel_auth_resp {
	__u32 magic;
	__u16 version;
	__u16 flags;
	__u32 size;
	__u32 status;
	__u8 nonce[WX_KERNEL_AUTH_NONCE_SIZE];
	__u8 boot_id[WX_KERNEL_AUTH_BOOT_ID_SIZE];
	__u64 ktime_ns;
};

#endif /* _UAPI_LINUX_WX_KERNEL_AUTH_H */
