#include <linux/string.h>   // for memset / memcpy
#include <linux/random.h>
#include <linux/kernel.h>

#if 0
static const char *http_fmt =
	"GET / HTTP/1.1\r\n"
	"Host: %s\r\n"
	"Accept: */*\r\n"
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
	"(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36\r\n"
	"\r\n";
#endif

static const char *http_methods[] = {
	"GET",
	"HEAD",
	"POST",
};

static const char *http_paths[] = {
	"/",
	"/favicon.ico",
	"/api/v1/ping",
	"/live",
	"/status",
};

static const char *http_user_agents[] = {
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
	"(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
	"(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"curl/8.1.2",
};

inline unsigned char *build_http_request(unsigned char *buf, int *len, const char *host)
{
	int len_;
	const char *method = http_methods[prandom_u32() % ARRAY_SIZE(http_methods)];
	const char *path = http_paths[prandom_u32() % ARRAY_SIZE(http_paths)];
	const char *ua = http_user_agents[prandom_u32() % ARRAY_SIZE(http_user_agents)];

	if (!strcmp(method, "POST")) {
		len_ = snprintf((char *)buf, *len,
			"%s %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Accept: */*\r\n"
			"Content-Length: 0\r\n"
			"Connection: keep-alive\r\n"
			"\r\n",
			method, path, host, ua);
	} else {
		len_ = snprintf((char *)buf, *len,
			"%s %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Accept: */*\r\n"
			"Accept-Language: en-US,en;q=0.9\r\n"
			"Connection: keep-alive\r\n"
			"\r\n",
			method, path, host, ua);
	}
	if (len_ < 0) {
		printk("ERROR: snprintf(): %s", "failure");
		return buf;

	} else if (len_ >= *len) {
		printk("ERROR: hostname is too long");
		return buf;
	}

	*len = len_;

	return buf;
}
