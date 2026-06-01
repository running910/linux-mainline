/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_WX_KERNEL_ATTEST_H
#define _UAPI_LINUX_WX_KERNEL_ATTEST_H

#include <linux/types.h>

#define WX_KERNEL_ATTEST_MAGIC		0x57584154 /* "WXAT" */
#define WX_KERNEL_ATTEST_VERSION	1
#define WX_KERNEL_ATTEST_CHALLENGE	1

#define WX_KERNEL_ATTEST_SIG_RSA_SHA256	1

#define WX_KERNEL_ATTEST_NONCE_SIZE	32
#define WX_KERNEL_ATTEST_KERNEL_ID_SIZE	32
#define WX_KERNEL_ATTEST_BOOT_ID_SIZE	16
#define WX_KERNEL_ATTEST_SIGNATURE_SIZE	512

struct wx_kernel_attest_req {
	__u32 magic;
	__u16 version;
	__u16 flags;
	__u32 size;
	__u32 cmd;
	__u8 nonce[WX_KERNEL_ATTEST_NONCE_SIZE];
};

struct wx_kernel_attest_payload {
	__u32 magic;
	__u16 version;
	__u16 flags;
	__u32 size;
	__u32 cmd;
	__u32 key_id;
	__u32 sig_alg;
	__u8 nonce[WX_KERNEL_ATTEST_NONCE_SIZE];
	__u8 kernel_id[WX_KERNEL_ATTEST_KERNEL_ID_SIZE];
	__u8 boot_id[WX_KERNEL_ATTEST_BOOT_ID_SIZE];
	__u64 ktime_ns;
	__u64 feature_flags;
};

struct wx_kernel_attest_resp {
	struct wx_kernel_attest_payload payload;
	__u32 status;
	__u32 sig_len;
	__u8 signature[WX_KERNEL_ATTEST_SIGNATURE_SIZE];
};

#endif /* _UAPI_LINUX_WX_KERNEL_ATTEST_H */
