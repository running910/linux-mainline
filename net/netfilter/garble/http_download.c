#include <linux/string.h>
#include <linux/random.h>
#include <linux/kernel.h>

#include "http.h"

struct http_download_page_template {
	const char *path;
	const char *referer;
};

static const char * const http_download_live_names[] = {
	"v",
	"stream",
	"api",
	"media",
	"playlist",
	"audio",
	"data",
	"manifest",
	"file",
	"image",
	"video",
	"index",
	"master",
};

static const char * const http_download_media_dirs[] = {
	"",
	"video/",
	"photo/",
	"ai/",
	"api/",
	"api/v1/",
	"api/v2/",
	"media/",
	"stream/",
	"broadcast/",
	"vod/",
	"camera/",
	"audio/",
	"test/",
};

static const struct http_download_page_template http_download_pages[] = {
	{ "/en/download", "/en/" },
	{ "/download", "/" },
	{ "/download/firmware", "/" },
	{ "/download/developer", "/" },
	{ "/en/resource-center/download", "/en/" },
};

unsigned char *build_http_download_request(unsigned char *buf, int *len,
					   const char *host)
{
	char path[128];
	int len_;
	const char *ua = garble_http_random_user_agent();
	u32 profile = prandom_u32() % 100;

	if (!host)
		return NULL;

	if (profile < 35) {
		const char *name = http_download_live_names[prandom_u32() %
			ARRAY_SIZE(http_download_live_names)];
		const char *ext = (prandom_u32() & 1) ? "m3u8" : "ts";
		u32 id = (prandom_u32() % 30000) + 1;

		len_ = snprintf(path, sizeof(path), "/%s%u.%s", name, id, ext);
		if (len_ < 0 || len_ >= (int)sizeof(path)) {
			printk("ERROR: http download hls path is too long");
			return buf;
		}

		len_ = snprintf((char *)buf, *len,
			"GET %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Accept: application/vnd.apple.mpegurl\r\n"
			"Connection: keep-alive\r\n"
			"\r\n",
			path, host, ua);
	} else if (profile < 60) {
		const char *name = http_download_live_names[prandom_u32() %
			ARRAY_SIZE(http_download_live_names)];
		u32 id = (prandom_u32() % 30000) + 1;
		u32 end = (prandom_u32() % 60000) + 4096;

		len_ = snprintf(path, sizeof(path), "/live/%s%u.flv", name, id);
		if (len_ < 0 || len_ >= (int)sizeof(path)) {
			printk("ERROR: http download flv range path is too long");
			return buf;
		}

		len_ = snprintf((char *)buf, *len,
			"GET %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Accept: video/x-flv\r\n"
			"Range: bytes=0-%u\r\n"
			"Connection: keep-alive\r\n"
			"\r\n",
			path, host, ua, end);
	} else if (profile < 72) {
		u32 id = (prandom_u32() % 10000) + 1;

		len_ = snprintf(path, sizeof(path), "/live%u.flv", id);
		if (len_ < 0 || len_ >= (int)sizeof(path)) {
			printk("ERROR: http download flv upgrade path is too long");
			return buf;
		}

		len_ = snprintf((char *)buf, *len,
			"GET %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Accept: video/x-flv\r\n"
			"Connection: Upgrade\r\n"
			"\r\n",
			path, host, ua);
	} else if (profile < 87) {
		const char *dir = http_download_media_dirs[prandom_u32() %
			ARRAY_SIZE(http_download_media_dirs)];
		const char *ext = (prandom_u32() & 1) ? "mpd" : "m4s";
		u32 id = (prandom_u32() % 10000) + 1;

		len_ = snprintf(path, sizeof(path), "/%smanifest%u.%s",
				dir, id, ext);
		if (len_ < 0 || len_ >= (int)sizeof(path)) {
			printk("ERROR: http download dash path is too long");
			return buf;
		}

		len_ = snprintf((char *)buf, *len,
			"GET %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Connection: keep-alive\r\n"
			"\r\n",
			path, host, ua);
	} else if (profile < 95) {
		u32 nonce = prandom_u32();

		len_ = snprintf((char *)buf, *len,
			"GET /speedtest/latency.txt?x=%08x HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Accept: */*\r\n"
			"Connection: keep-alive\r\n"
			"\r\n",
			nonce, host, ua);
	} else {
		const struct http_download_page_template *tpl =
			&http_download_pages[prandom_u32() %
				ARRAY_SIZE(http_download_pages)];

		len_ = snprintf((char *)buf, *len,
			"GET %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: %s\r\n"
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
			"Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
			"Accept-Encoding: gzip, deflate, br\r\n"
			"Referer: https://%s%s\r\n"
			"Connection: keep-alive\r\n"
			"\r\n",
			tpl->path, host, ua, host, tpl->referer);
	}

	if (len_ < 0) {
		printk("ERROR: snprintf(): %s", "failure");
		return buf;
	} else if (len_ >= *len) {
		printk("ERROR: http download request is too long");
		return buf;
	}

	*len = len_;

	return buf;
}
