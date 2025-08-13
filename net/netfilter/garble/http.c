#include <linux/string.h>   // for memset / memcpy
#include <linux/random.h>

static const char *http_fmt =
	"GET / HTTP/1.1\r\n"
	"Host: %s\r\n"
	"Accept: */*\r\n"
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
	"(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36\r\n"
	"\r\n";

inline unsigned char *build_http_request(unsigned char *buf, int *len, const char *host)
{
	int len_;

	len_ = snprintf((char *)buf, *len, http_fmt, host);
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
