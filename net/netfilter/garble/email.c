#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/version.h>

#include "email.h"

#define EMAIL_NAME_BUF_COUNT	64
#define EMAIL_NAME_BUF_LEN	64
#define EMAIL_ADDR_BUF_COUNT	64
#define EMAIL_ADDR_BUF_LEN	128

static char email_name_buf[EMAIL_NAME_BUF_COUNT][EMAIL_NAME_BUF_LEN];
static char email_addr_buf[EMAIL_ADDR_BUF_COUNT][EMAIL_ADDR_BUF_LEN];
static atomic_t email_name_idx = ATOMIC_INIT(0);
static atomic_t email_addr_idx = ATOMIC_INIT(0);

static const char *email_surnames[] = {
	"wang", "li", "zhang", "liu", "chen", "yang", "zhao", "huang",
	"zhou", "wu", "xu", "sun", "ma", "zhu", "hu", "guo",
	"he", "gao", "lin", "luo", "zheng", "liang", "xie", "song",
	"tang", "deng", "han", "cao", "xiao", "feng", "yu", "du",
};

static const char *email_given_names[] = {
	"wei", "fang", "li", "na", "min", "jing", "lei", "qiang",
	"tao", "yan", "jun", "hao", "lin", "hui", "jie", "bin",
	"gang", "juan", "qian", "xia", "ming", "peng", "yong", "chao",
	"ying", "ting", "shan", "dan", "fei", "kai", "rui", "xin",
};

static const char *email_given_prefixes[] = {
	"xiao", "jia", "zi", "yu", "wen", "shu", "hai", "guo",
	"ming", "hong", "li", "mei", "yong", "zhi", "jun", "qing",
};

static const char *email_jobs[] = {
	"designer", "engineer", "teacher", "doctor", "manager", "sales",
	"coder", "admin", "finance", "hr", "product", "tester",
	"support", "editor", "driver", "student", "dev", "ops",
};

static const char *email_interests[] = {
	"music", "photo", "movie", "travel", "runner", "fitness",
	"coffee", "guitar", "basketball", "football", "reading", "coding",
	"gaming", "food", "bike", "camera", "design", "blog",
};

static const char *email_seps[] = {
	"", "", "", "_", "_", ".", "-"
};

static const char *email_domains[] = {
	"163.com",
	"qq.com",
	"126.com",
	"foxmail.com",
	"aliyun.com",
	"139.com",
	"sina.com",
	"sina.cn",
	"outlook.com",
	"hotmail.com",
	"yeah.net",
	"188.com",
	"sohu.com",
	"21cn.com",
	"189.com",
	"gmail.com",
	"yahoo.com",
	"outlook.com",
	"hotmail.com",
	"live.com",
	"msn.com",
	"icloud.com",
	"me.com",
	"mac.com",
	"aol.com",
	"proton.me",
	"protonmail.com",
	"zoho.com",
	"gmx.com",
	"gmx.net",
	"mail.com",
	"yandex.com",
	"qq.com",
	"foxmail.com",
	"vip.qq.com",
	"163.com",
	"126.com",
	"yeah.net",
	"sina.com",
	"sina.cn",
	"sohu.com",
	"aliyun.com",
	"tom.com",
	"139.com",
	"189.cn",
	"21cn.com",
	"naver.com",
	"daum.net",
	"hanmail.net",
	"nate.com",
	"kakao.com",
	"rediffmail.com",
	"indiatimes.com",
	"sify.com",
};

static inline const char *email_pick(const char * const items[], int count)
{
	return items[prandom_u32() % count];
}

static inline int email_birth_year(void)
{
	return 1985 + (prandom_u32() % 22);
}

static inline int email_birth_month(void)
{
	return 1 + (prandom_u32() % 12);
}

static inline char *email_next_buf(void)
{
	u32 idx = (u32)atomic_inc_return(&email_name_idx);

	return email_name_buf[idx % EMAIL_NAME_BUF_COUNT];
}

static inline char *email_next_addr_buf(void)
{
	u32 idx = (u32)atomic_inc_return(&email_addr_idx);

	return email_addr_buf[idx % EMAIL_ADDR_BUF_COUNT];
}

static void email_make_given(char *buf, size_t len)
{
	if (prandom_u32() % 100 < 35)
		scnprintf(buf, len, "%s%s",
			  email_pick(email_given_prefixes,
				     ARRAY_SIZE(email_given_prefixes)),
			  email_pick(email_given_names,
				     ARRAY_SIZE(email_given_names)));
	else
		scnprintf(buf, len, "%s",
			  email_pick(email_given_names,
				     ARRAY_SIZE(email_given_names)));
}

inline const char *get_email_name(void)
{
	char given[24];
	char given2[24];
	char *buf = email_next_buf();
	const char *surname = email_pick(email_surnames,
					 ARRAY_SIZE(email_surnames));
	const char *sep = email_pick(email_seps, ARRAY_SIZE(email_seps));
	int year = email_birth_year();
	int month = email_birth_month();
	u32 mode = prandom_u32() % 100;

	email_make_given(given, sizeof(given));
	email_make_given(given2, sizeof(given2));

	if (mode < 38) {
		scnprintf(buf, EMAIL_NAME_BUF_LEN, "%s%s%d", given, surname,
			  year);
	} else if (mode < 58) {
		scnprintf(buf, EMAIL_NAME_BUF_LEN, "%s%s%s%d", surname, sep,
			  given, year);
	} else if (mode < 72) {
		scnprintf(buf, EMAIL_NAME_BUF_LEN, "%s%s", surname, given);
	} else if (mode < 82) {
		scnprintf(buf, EMAIL_NAME_BUF_LEN, "%s%s", given, given2);
	} else if (mode < 91) {
		scnprintf(buf, EMAIL_NAME_BUF_LEN, "%s_%s",
			  email_pick(email_jobs, ARRAY_SIZE(email_jobs)), given);
	} else if (mode < 97) {
		scnprintf(buf, EMAIL_NAME_BUF_LEN, "%s%s%s",
			  email_pick(email_interests, ARRAY_SIZE(email_interests)),
			  sep, given);
	} else {
		scnprintf(buf, EMAIL_NAME_BUF_LEN, "%s%s%02d", given, surname,
			  month);
	}

	return buf;
}

inline const char *get_email(void)
{
	const char *name = get_email_name();
	const char *domain = email_pick(email_domains, ARRAY_SIZE(email_domains));
	char *buf = email_next_addr_buf();

	scnprintf(buf, EMAIL_ADDR_BUF_LEN, "%s@%s", name, domain);

	return buf;
}
