/*
 * TURN Allocate Request packet generator - Kernel version
 * Generate TURN payload (encoded in STUN framing), no IP/UDP headers
 * Pre-allocated crypto transforms for interrupt context safety
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/md5.h>

/* TURN message constants (STUN framing) */
#define TURN_MAGIC_COOKIE 0x2112A442
#define TURN_MSG_ALLOCATE_REQUEST 0x0003

/* TURN attribute types */
#define TURN_ATTR_REQUESTED_TRANSPORT 0x0019
#define TURN_ATTR_USERNAME 0x0006
#define TURN_ATTR_REALM 0x0014
#define TURN_ATTR_NONCE 0x0015
#define TURN_ATTR_MESSAGE_INTEGRITY 0x0008

/* Utility macros */
#define ALIGN_4(len) (((len) + 3) & ~3)
#define MAX_DESC_SIZE 256  /* Maximum expected shash_desc size */

/* Digest sizes for kernel crypto API */
#define MD5_DIGEST_SIZE 16
#define SHA1_DIGEST_SIZE 20

/* Pre-allocated crypto transforms */
static struct crypto_shash *md5_tfm = NULL;
static struct crypto_shash *hmac_sha1_tfm = NULL;

/* TURN data structures (STUN framing) */
struct stun_attribute {
	uint16_t type;
	uint16_t length;
	uint8_t value[0];
} __attribute__((packed));

struct stun_header {
	uint16_t msg_type;
	uint16_t msg_length;
	uint32_t magic_cookie;
	uint8_t transaction_id[12];
} __attribute__((packed));

/*
 * Cleanup crypto transforms during module unload
 */
void stun_crypto_cleanup(void)
{
	if (md5_tfm) {
		crypto_free_shash(md5_tfm);
		md5_tfm = NULL;
	}
	
	if (hmac_sha1_tfm) {
		crypto_free_shash(hmac_sha1_tfm);
		hmac_sha1_tfm = NULL;
	}

	pr_info("TURN crypto transforms cleaned up\n");
}

/*
 * Initialize crypto transforms during module load
 * Called in process context, safe for sleeping operations
 */
int stun_crypto_init(void)
{
	int ret = 0;

	md5_tfm = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(md5_tfm)) {
		pr_err("Failed to allocate MD5 transform\n");
		ret = PTR_ERR(md5_tfm);
		md5_tfm = NULL;
		goto error;
	}

	hmac_sha1_tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
	if (IS_ERR(hmac_sha1_tfm)) {
		pr_err("Failed to allocate HMAC-SHA1 transform\n");
		ret = PTR_ERR(hmac_sha1_tfm);
		hmac_sha1_tfm = NULL;
		goto error;
	}

	pr_info("TURN crypto transforms initialized successfully\n");
	return 0;

error:
	stun_crypto_cleanup();
	return ret;
}

/*
 * Generate random alphanumeric string - kernel version
 */
static void generate_random_string_kernel(char *buf, int len)
{
	static const char alphanum[] = 
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789";
	int i;
	unsigned int rand_val;

	for (i = 0; i < len; i++) {
		get_random_bytes(&rand_val, sizeof(rand_val));
		buf[i] = alphanum[rand_val % (sizeof(alphanum) - 1)];
	}
	buf[len] = '\0';
}

/*
 * Calculate MD5 hash using pre-allocated transform
 * Safe for interrupt context - no dynamic allocation
 */
static int calculate_md5_kernel(const uint8_t *data, size_t len, uint8_t *digest)
{
	struct shash_desc *desc;
	char desc_buf[sizeof(struct shash_desc) + MAX_DESC_SIZE];
	int ret;

	if (!md5_tfm) {
		pr_err("MD5 transform not initialized\n");
		return -EINVAL;
	}

	desc = (struct shash_desc *)desc_buf;
	desc->tfm = md5_tfm;

	ret = crypto_shash_init(desc);
	if (ret) {
		pr_err("MD5 init failed: %d\n", ret);
		return ret;
	}

	ret = crypto_shash_update(desc, data, len);
	if (ret) {
		pr_err("MD5 update failed: %d\n", ret);
		return ret;
	}

	ret = crypto_shash_final(desc, digest);
	if (ret) {
		pr_err("MD5 final failed: %d\n", ret);
		return ret;
	}

	return 0;
}

/*
 * Calculate HMAC-SHA1 using pre-allocated transform
 * Safe for interrupt context - no dynamic allocation
 */
static int calculate_hmac_sha1_kernel(const uint8_t *key, size_t key_len,
				      const uint8_t *data, size_t data_len,
				      uint8_t *digest)
{
	struct shash_desc *desc;
	char desc_buf[sizeof(struct shash_desc) + MAX_DESC_SIZE];
	int ret;

	if (!hmac_sha1_tfm) {
		pr_err("HMAC-SHA1 transform not initialized\n");
		return -EINVAL;
	}

	desc = (struct shash_desc *)desc_buf;
	desc->tfm = hmac_sha1_tfm;

	/* Set HMAC key */
	ret = crypto_shash_setkey(hmac_sha1_tfm, key, key_len);
	if (ret) {
		pr_err("Failed to set HMAC key: %d\n", ret);
		return ret;
	}

	ret = crypto_shash_init(desc);
	if (ret) {
		pr_err("HMAC-SHA1 init failed: %d\n", ret);
		return ret;
	}

	ret = crypto_shash_update(desc, data, data_len);
	if (ret) {
		pr_err("HMAC-SHA1 update failed: %d\n", ret);
		return ret;
	}

	ret = crypto_shash_final(desc, digest);
	if (ret) {
		pr_err("HMAC-SHA1 final failed: %d\n", ret);
		return ret;
	}

	return 0;
}

/*
 * Generate TURN allocate request packet - kernel version
 * Uses pre-allocated crypto transforms for interrupt context safety
 * 
 * @packet: Output buffer for TURN packet
 * @max_len: Input maximum length of output buffer, output actual packet length
 * 
 * Returns: 0 on success, negative error code on failure
 */
int generate_turn_allocate_request_kernel(uint8_t *packet, int *max_len)
{
	struct stun_header *hdr;
	uint8_t *attr_ptr;
	int attr_len;
	char username[32];
	char nonce[17];
	const char *realm;
	int i;
	uint8_t key[MD5_DIGEST_SIZE];
	uint8_t hmac_buf[SHA1_DIGEST_SIZE];
	char key_input[256];
	int ret;
	int username_padded_len;
	int realm_padded_len;
	int nonce_padded_len;
	int total_len;
	int msg_len;
	struct stun_attribute *transport_attr;
	struct stun_attribute *username_attr;
	struct stun_attribute *realm_attr;
	struct stun_attribute *nonce_attr;
	struct stun_attribute *integrity_attr;
	char password[17];

	/* Check if crypto transforms are initialized */
	if (!md5_tfm || !hmac_sha1_tfm) {
		pr_err("Crypto transforms not initialized\n");
		return -EINVAL;
	}

	/* Initialize all local variables */
	hdr = (struct stun_header *)packet;
	attr_ptr = packet + sizeof(struct stun_header);
	attr_len = 0;
	realm = "turn.mcs.dingtalk.com";
	username_padded_len = 0;
	realm_padded_len = 0;
	nonce_padded_len = 0;
	total_len = 0;
	msg_len = 0;
	transport_attr = NULL;
	username_attr = NULL;
	realm_attr = NULL;
	nonce_attr = NULL;
	integrity_attr = NULL;

	memset(username, 0, sizeof(username));
	memset(nonce, 0, sizeof(nonce));
	memset(key, 0, sizeof(key));
	memset(hmac_buf, 0, sizeof(hmac_buf));
	memset(key_input, 0, sizeof(key_input));
	memset(password, 0, sizeof(password));

	/* Check buffer size */
	if (*max_len < sizeof(struct stun_header)) {
		pr_err("Buffer too small for TURN header\n");
		return -EINVAL;
	}

	/* Generate random transaction ID */
	for (i = 0; i < 12; i++) {
		get_random_bytes(&hdr->transaction_id[i], sizeof(uint8_t));
	}

	/* Generate username: XXX@XXXXXXXX */
	generate_random_string_kernel(username, 3);
	username[3] = '@';
	generate_random_string_kernel(username + 4, 8);
	username[12] = '\0';

	/* Generate password (16 alphanumeric characters) */
	generate_random_string_kernel(password, 16);
	password[16] = '\0';

	/* Generate nonce (16 alphanumeric characters) */
	generate_random_string_kernel(nonce, 16);
	nonce[16] = '\0';

	/* Build TURN header */
	hdr->msg_type = htons(TURN_MSG_ALLOCATE_REQUEST);
	hdr->magic_cookie = htonl(TURN_MAGIC_COOKIE);
	hdr->msg_length = 0; /* Will be set later */

	/* 1. REQUESTED-TRANSPORT attribute */
	if (attr_ptr + sizeof(struct stun_attribute) + 4 > packet + *max_len) {
		pr_err("Buffer overflow in transport attribute\n");
		return -ENOSPC;
	}
	
	transport_attr = (struct stun_attribute *)attr_ptr;
	transport_attr->type = htons(TURN_ATTR_REQUESTED_TRANSPORT);
	transport_attr->length = htons(4);
	transport_attr->value[0] = 0x11; /* UDP protocol */
	transport_attr->value[1] = 0x00;
	transport_attr->value[2] = 0x00;
	transport_attr->value[3] = 0x00;
	attr_ptr += sizeof(struct stun_attribute) + 4;
	attr_len += sizeof(struct stun_attribute) + 4;

	/* 2. USERNAME attribute */
	username_padded_len = ALIGN_4(strlen(username));
	if (attr_ptr + sizeof(struct stun_attribute) + username_padded_len > packet + *max_len) {
		pr_err("Buffer overflow in username attribute\n");
		return -ENOSPC;
	}
	
	username_attr = (struct stun_attribute *)attr_ptr;
	username_attr->type = htons(TURN_ATTR_USERNAME);
	username_attr->length = htons(strlen(username));
	memcpy(username_attr->value, username, strlen(username));
	memset(username_attr->value + strlen(username), 0, username_padded_len - strlen(username));
	attr_ptr += sizeof(struct stun_attribute) + username_padded_len;
	attr_len += sizeof(struct stun_attribute) + username_padded_len;

	/* 3. REALM attribute */
	realm_padded_len = ALIGN_4(strlen(realm));
	if (attr_ptr + sizeof(struct stun_attribute) + realm_padded_len > packet + *max_len) {
		pr_err("Buffer overflow in realm attribute\n");
		return -ENOSPC;
	}
	
	realm_attr = (struct stun_attribute *)attr_ptr;
	realm_attr->type = htons(TURN_ATTR_REALM);
	realm_attr->length = htons(strlen(realm));
	memcpy(realm_attr->value, realm, strlen(realm));
	memset(realm_attr->value + strlen(realm), 0, realm_padded_len - strlen(realm));
	attr_ptr += sizeof(struct stun_attribute) + realm_padded_len;
	attr_len += sizeof(struct stun_attribute) + realm_padded_len;

	/* 4. NONCE attribute */
	nonce_padded_len = ALIGN_4(strlen(nonce));
	if (attr_ptr + sizeof(struct stun_attribute) + nonce_padded_len > packet + *max_len) {
		pr_err("Buffer overflow in nonce attribute\n");
		return -ENOSPC;
	}
	
	nonce_attr = (struct stun_attribute *)attr_ptr;
	nonce_attr->type = htons(TURN_ATTR_NONCE);
	nonce_attr->length = htons(strlen(nonce));
	memcpy(nonce_attr->value, nonce, strlen(nonce));
	memset(nonce_attr->value + strlen(nonce), 0, nonce_padded_len - strlen(nonce));
	attr_ptr += sizeof(struct stun_attribute) + nonce_padded_len;
	attr_len += sizeof(struct stun_attribute) + nonce_padded_len;

	/* 5. MESSAGE-INTEGRITY attribute with generated password */
	/* First calculate HMAC for message without MESSAGE-INTEGRITY */
	hdr->msg_length = htons(attr_len);
	msg_len = sizeof(struct stun_header) + attr_len;

	/* Calculate key: MD5(username:realm:password) */
	snprintf(key_input, sizeof(key_input), "%s:%s:%s", username, realm, password);
	
	ret = calculate_md5_kernel((const uint8_t *)key_input, strlen(key_input), key);
	if (ret) {
		pr_err("Failed to calculate MD5 hash\n");
		return ret;
	}

	/* Calculate HMAC-SHA1 */
	ret = calculate_hmac_sha1_kernel(key, MD5_DIGEST_SIZE,
					 (const uint8_t *)packet, msg_len,
					 hmac_buf);
	if (ret) {
		pr_err("Failed to calculate HMAC-SHA1\n");
		return ret;
	}

	/* Check buffer space for integrity attribute */
	if (attr_ptr + sizeof(struct stun_attribute) + SHA1_DIGEST_SIZE > packet + *max_len) {
		pr_err("Buffer overflow in integrity attribute\n");
		return -ENOSPC;
	}

	/* Add MESSAGE-INTEGRITY attribute */
	integrity_attr = (struct stun_attribute *)attr_ptr;
	integrity_attr->type = htons(TURN_ATTR_MESSAGE_INTEGRITY);
	integrity_attr->length = htons(SHA1_DIGEST_SIZE);
	memcpy(integrity_attr->value, hmac_buf, SHA1_DIGEST_SIZE);
	attr_ptr += sizeof(struct stun_attribute) + SHA1_DIGEST_SIZE;
	attr_len += sizeof(struct stun_attribute) + SHA1_DIGEST_SIZE;

	/* Update final message length */
	hdr->msg_length = htons(attr_len);

	/* Calculate total packet length */
	total_len = sizeof(struct stun_header) + attr_len;
	
	if (total_len > *max_len) {
		pr_err("Generated packet exceeds buffer size: %d > %d\n", total_len, *max_len);
		return -ENOSPC;
	}

	/* Output actual packet length */
	*max_len = total_len;

	return 0;
}

inline unsigned char *build_turn_payload(unsigned char *buf, int *out_len)
{

	if (generate_turn_allocate_request_kernel(buf, out_len) == 0) {
		return buf;
	} else {
		return NULL;
	}
}


