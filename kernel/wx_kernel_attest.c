// SPDX-License-Identifier: GPL-2.0
#include <crypto/akcipher.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/export.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/wx_kernel_attest.h>

#define WX_KEY_ID		1
#define WX_FEATURE_FLAGS	0
#define WX_RSA_PRIV_KEY_MAX	2048
#define WX_KERNEL_ATTEST_LANES	16

static u8 wx_kernel_attest_boot_id[WX_KERNEL_ATTEST_BOOT_ID_SIZE];
static DEFINE_MUTEX(wx_kernel_attest_lock);

static const u8 wx_kernel_attest_kernel_id[WX_KERNEL_ATTEST_KERNEL_ID_SIZE] = {
	0x57, 0x58, 0x2d, 0x4b, 0x45, 0x52, 0x4e, 0x45,
	0x4c, 0x2d, 0x41, 0x54, 0x54, 0x45, 0x53, 0x54,
	0x2d, 0x56, 0x31, 0x00, 0x8d, 0x91, 0x25, 0x6b,
	0x35, 0xca, 0x47, 0x1b, 0xf0, 0x19, 0x4a, 0x6e,
};

/*
 * The signing key material is build-time encoded into
 * kernel/wx_kernel_attest_key_blob.c.  This is an obfuscation layer only:
 * systems that can provide a non-exportable TPM/TEE key should use that
 * instead of embedding product keys in the kernel image.
 */
extern const u8 wx_kernel_attest_vec0[];
extern const u8 wx_kernel_attest_vec1[];
extern const u8 wx_kernel_attest_vec2[];
extern const u8 wx_kernel_attest_vec3[];
extern const u8 wx_kernel_attest_vec4[];
extern const u8 wx_kernel_attest_vec5[];
extern const u8 wx_kernel_attest_vec6[];
extern const u8 wx_kernel_attest_vec7[];
extern const u8 wx_kernel_attest_vec8[];
extern const u8 wx_kernel_attest_vec9[];
extern const u8 wx_kernel_attest_vec10[];
extern const u8 wx_kernel_attest_vec11[];
extern const u8 wx_kernel_attest_vec12[];
extern const u8 wx_kernel_attest_vec13[];
extern const u8 wx_kernel_attest_vec14[];
extern const u8 wx_kernel_attest_vec15[];
extern const unsigned int wx_kernel_attest_vec_len[];
extern const unsigned int wx_kernel_attest_key_len;
extern const u8 wx_kernel_attest_meta0[];
extern const u8 wx_kernel_attest_meta1[];
extern const u8 wx_kernel_attest_meta2[];

static u8 wx_kernel_attest_meta_salt(unsigned int idx)
{
	return wx_kernel_attest_meta1[idx] ^ (u8)(0xa7 + idx * 29);
}

static u32 wx_kernel_attest_seed(void)
{
	u32 seed = 0;
	unsigned int i;

	for (i = 0; i < 4; i++)
		seed |= (u32)(wx_kernel_attest_meta0[i] ^
			      wx_kernel_attest_meta_salt(i)) << (i * 8);

	return seed;
}

static unsigned int wx_kernel_attest_meta_u16(unsigned int idx)
{
	u8 lo = wx_kernel_attest_meta0[idx] ^
		wx_kernel_attest_meta_salt(idx);
	u8 hi = wx_kernel_attest_meta0[idx + 1] ^
		wx_kernel_attest_meta_salt(idx + 1);

	return lo | ((unsigned int)hi << 8);
}

static u8 wx_kernel_attest_mask_byte(u32 seed, unsigned int idx)
{
	u32 x = seed;

	x += idx * 1103515245U;
	x += (idx + 1) * (idx + 17) * 97U;

	return (x >> ((idx & 3) * 8)) & 0xff;
}

static int wx_kernel_attest_lane_map(unsigned int lane_to_vec[])
{
	bool seen[WX_KERNEL_ATTEST_LANES] = { false };
	unsigned int vec;

	/*
	 * meta2 encodes the build-time physical vec -> logical lane order.
	 * Example: if encoded vec1 resolves to lane9, vec1 contains the
	 * bytes for logical lane9.  Rebuild the inverse lane -> vec map
	 * here so the restore loop can fetch bytes by logical lane.
	 */
	for (vec = 0; vec < WX_KERNEL_ATTEST_LANES; vec++) {
		unsigned int lane;

		lane = wx_kernel_attest_meta2[vec] ^
		       wx_kernel_attest_meta_salt((vec + 3) & 7) ^
		       (u8)(0x3d + vec * 41);
		if (lane >= WX_KERNEL_ATTEST_LANES || seen[lane])
			return -EINVAL;

		seen[lane] = true;
		lane_to_vec[lane] = vec;
	}

	return 0;
}

static int wx_kernel_attest_restore_rsa_key(u8 *key, unsigned int *key_len,
					    unsigned int max_len)
{
	const u8 *vecs[WX_KERNEL_ATTEST_LANES] = {
		wx_kernel_attest_vec0,
		wx_kernel_attest_vec1,
		wx_kernel_attest_vec2,
		wx_kernel_attest_vec3,
		wx_kernel_attest_vec4,
		wx_kernel_attest_vec5,
		wx_kernel_attest_vec6,
		wx_kernel_attest_vec7,
		wx_kernel_attest_vec8,
		wx_kernel_attest_vec9,
		wx_kernel_attest_vec10,
		wx_kernel_attest_vec11,
		wx_kernel_attest_vec12,
		wx_kernel_attest_vec13,
		wx_kernel_attest_vec14,
		wx_kernel_attest_vec15,
	};
	unsigned int lane_to_vec[WX_KERNEL_ATTEST_LANES];
	unsigned int used[WX_KERNEL_ATTEST_LANES] = { 0 };
	unsigned int offset, stride, slot;
	u32 seed;
	int ret;

	if (!wx_kernel_attest_key_len ||
	    wx_kernel_attest_key_len > WX_RSA_PRIV_KEY_MAX)
		return -EINVAL;

	if (max_len < wx_kernel_attest_key_len)
		return -ENOSPC;

	seed = wx_kernel_attest_seed();
	stride = wx_kernel_attest_meta_u16(4);
	offset = wx_kernel_attest_meta_u16(6);
	if (!stride || offset >= wx_kernel_attest_key_len)
		return -EINVAL;

	ret = wx_kernel_attest_lane_map(lane_to_vec);
	if (ret)
		return ret;

	for (slot = 0; slot < wx_kernel_attest_key_len; slot++) {
		unsigned int idx, lane, vec;
		u8 encoded, mask;

		idx = (slot * stride + offset) % wx_kernel_attest_key_len;
		lane = (slot + wx_kernel_attest_mask_byte(seed, idx) +
			wx_kernel_attest_meta_salt(slot & 7)) %
		       WX_KERNEL_ATTEST_LANES;
		/* The logical lane is intentionally not the physical array. */
		vec = lane_to_vec[lane];
		if (used[vec] >= wx_kernel_attest_vec_len[vec])
			return -EINVAL;

		encoded = vecs[vec][used[vec]++];
		mask = wx_kernel_attest_mask_byte(seed, idx) ^
		       (u8)(idx * 31 + 165) ^
		       (u8)(slot * 17 +
			    wx_kernel_attest_meta_salt((idx + slot) & 7));
		key[idx] = encoded ^ mask;
	}

	for (slot = 0; slot < WX_KERNEL_ATTEST_LANES; slot++) {
		if (used[slot] != wx_kernel_attest_vec_len[slot])
			return -EINVAL;
	}

	*key_len = wx_kernel_attest_key_len;
	return 0;
}

static void wx_kernel_attest_init_boot_id(void)
{
	static bool initialized;

	if (likely(READ_ONCE(initialized)))
		return;

	mutex_lock(&wx_kernel_attest_lock);
	if (!initialized) {
		get_random_bytes(wx_kernel_attest_boot_id,
				 sizeof(wx_kernel_attest_boot_id));
		WRITE_ONCE(initialized, true);
	}
	mutex_unlock(&wx_kernel_attest_lock);
}

static int wx_kernel_attest_sha256(const void *data, unsigned int len,
				   u8 digest[32])
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	unsigned int desc_size;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc_size = sizeof(*desc) + crypto_shash_descsize(tfm);
	desc = kzalloc(desc_size, GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	desc->tfm = tfm;
	ret = crypto_shash_digest(desc, data, len, digest);

	memzero_explicit(desc, desc_size);
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

static int wx_kernel_attest_rsa_sign(const u8 digest[32], u8 *sig,
				     u32 *sig_len)
{
	struct crypto_akcipher *tfm;
	struct akcipher_request *req;
	struct scatterlist src, dst;
	DECLARE_CRYPTO_WAIT(wait);
	u8 *digest_buf;
	u8 *key;
	u8 *sig_buf;
	unsigned int key_len = 0;
	unsigned int out_len;
	int ret;

	digest_buf = kmemdup(digest, 32, GFP_KERNEL);
	if (!digest_buf)
		return -ENOMEM;

	key = kzalloc(WX_RSA_PRIV_KEY_MAX, GFP_KERNEL);
	if (!key) {
		ret = -ENOMEM;
		goto out_free_digest;
	}

	sig_buf = kzalloc(WX_KERNEL_ATTEST_SIGNATURE_SIZE, GFP_KERNEL);
	if (!sig_buf) {
		ret = -ENOMEM;
		goto out_free_key;
	}

	ret = wx_kernel_attest_restore_rsa_key(key, &key_len,
					       WX_RSA_PRIV_KEY_MAX);
	if (ret)
		goto out_free_sig;

	tfm = crypto_alloc_akcipher("pkcs1pad(rsa,sha256)", 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		goto out_free_sig;
	}

	ret = crypto_akcipher_set_priv_key(tfm, key, key_len);
	if (ret)
		goto out_free_tfm;

	out_len = crypto_akcipher_maxsize(tfm);
	if (out_len > WX_KERNEL_ATTEST_SIGNATURE_SIZE) {
		ret = -EOVERFLOW;
		goto out_free_tfm;
	}

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	sg_init_one(&src, digest_buf, 32);
	sg_init_one(&dst, sig_buf, out_len);
	akcipher_request_set_crypt(req, &src, &dst, 32, out_len);
	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &wait);

	ret = crypto_wait_req(crypto_akcipher_sign(req), &wait);
	if (!ret) {
		*sig_len = req->dst_len;
		memcpy(sig, sig_buf, *sig_len);
		if (*sig_len < WX_KERNEL_ATTEST_SIGNATURE_SIZE)
			memset(sig + *sig_len, 0,
			       WX_KERNEL_ATTEST_SIGNATURE_SIZE - *sig_len);
	}

	akcipher_request_free(req);
out_free_tfm:
	crypto_free_akcipher(tfm);
out_free_sig:
	memzero_explicit(sig_buf, WX_KERNEL_ATTEST_SIGNATURE_SIZE);
	kfree(sig_buf);
out_free_key:
	memzero_explicit(key, WX_RSA_PRIV_KEY_MAX);
	kfree(key);
out_free_digest:
	memzero_explicit(digest_buf, 32);
	kfree(digest_buf);
	return ret;
}

int wx_kernel_attest_challenge(const struct wx_kernel_attest_req *req,
			       struct wx_kernel_attest_resp *resp)
{
	u8 digest[32];
	int ret;

	if (!req || !resp)
		return -EINVAL;

	if (req->magic != WX_KERNEL_ATTEST_MAGIC ||
	    req->version != WX_KERNEL_ATTEST_VERSION ||
	    req->size < sizeof(*req) ||
	    req->cmd != WX_KERNEL_ATTEST_CHALLENGE)
		return -EINVAL;

	wx_kernel_attest_init_boot_id();

	memset(resp, 0, sizeof(*resp));
	resp->payload.magic = WX_KERNEL_ATTEST_MAGIC;
	resp->payload.version = WX_KERNEL_ATTEST_VERSION;
	resp->payload.size = sizeof(resp->payload);
	resp->payload.cmd = WX_KERNEL_ATTEST_CHALLENGE;
	resp->payload.key_id = WX_KEY_ID;
	resp->payload.sig_alg = WX_KERNEL_ATTEST_SIG_RSA_SHA256;
	memcpy(resp->payload.nonce, req->nonce, sizeof(resp->payload.nonce));
	memcpy(resp->payload.kernel_id, wx_kernel_attest_kernel_id,
	       sizeof(resp->payload.kernel_id));
	memcpy(resp->payload.boot_id, wx_kernel_attest_boot_id,
	       sizeof(resp->payload.boot_id));
	resp->payload.ktime_ns = ktime_get_ns();
	resp->payload.feature_flags = WX_FEATURE_FLAGS;

	ret = wx_kernel_attest_sha256(&resp->payload, sizeof(resp->payload),
				      digest);
	if (ret)
		return ret;

	ret = wx_kernel_attest_rsa_sign(digest, resp->signature,
					&resp->sig_len);
	memzero_explicit(digest, sizeof(digest));
	return ret;
}
EXPORT_SYMBOL_GPL(wx_kernel_attest_challenge);

SYSCALL_DEFINE3(wx_kernel_attest, unsigned int, cmd,
		struct wx_kernel_attest_req __user *, ureq,
		struct wx_kernel_attest_resp __user *, uresp)
{
	struct wx_kernel_attest_req req;
	struct wx_kernel_attest_resp resp;
	int ret;

	if (cmd != WX_KERNEL_ATTEST_CHALLENGE)
		return -EINVAL;

	if (copy_from_user(&req, ureq, sizeof(req)))
		return -EFAULT;

	ret = wx_kernel_attest_challenge(&req, &resp);
	if (ret)
		return ret;

	if (copy_to_user(uresp, &resp, sizeof(resp)))
		return -EFAULT;

	return 0;
}
