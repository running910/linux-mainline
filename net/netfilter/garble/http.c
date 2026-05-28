#include <linux/string.h>   // for memset / memcpy
#include <linux/random.h>
#include <linux/kernel.h>

#include "http.h"

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

#if 0
static const char *http_user_agents[] = {
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
	"(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
	"(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"curl/8.1.2",
};
#endif

static const char *http_user_agents[] = {

	/* ===== 竞品抓出来的 ===== */
	"Doubao/1.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_10 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/605.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_10 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/607.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/605.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/606.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/613.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/609.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/611.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/612.1",
	"Mozilla/5.0 (Linux; Android 12; 23113RKC6C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6795.109 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; 23113RKC6C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6589.44 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; CPH2493) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6963.174 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; M2012K11AC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.7752.124 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.6858.141 Mobile Safari/537.36 HuaweiBrowser/16.0.39.207",
	"Mozilla/5.0 (Linux; Android 12; Pixel 8 Build/AP3A.241093.752; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.6716.140 Mobile Safari/537.36 TBS/403020 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 12; SM-S918B Build/AP3A.240954.626; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/138.0.7460.148 Mobile Safari/537.36 TBS/431033 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 12; V2362A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6522.132 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; V2362A Build/AP3A.240553.049; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.6055.92 Mobile Safari/537.36 TBS/495613 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 13; 23113RKC6C Build/AP3A.240175.344; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/127.0.6266.153 Mobile Safari/537.36 TBS/479363 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 13; 23113RKC6C Build/AP3A.240650.934; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.7695.45 Mobile Safari/537.36 TBS/436675 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 13; CPH2493) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6102.126 Mobile Safari/537.36 HuaweiBrowser/16.0.44.157",
	"Mozilla/5.0 (Linux; Android 13; CPH2493 Build/AP3A.240760.491; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/132.0.7498.100 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; CTR-L91) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.7144.47 Mobile Safari/537.36 HuaweiBrowser/16.0.6.192",
	"Mozilla/5.0 (Linux; Android 13; M2012K11AC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.6250.175 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; PFEM10 Build/AP3A.240187.211; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.6094.105 Mobile Safari/537.36 TBS/496320 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 13; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6461.193 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-S918B Build/AP3A.240635.979; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7502.184 Mobile Safari/537.36 TBS/479886 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 13; V2362A Build/AP3A.241093.926; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.7265.131 Mobile Safari/537.36 TBS/400659 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36",
	"Mozilla/5.0 (Linux; Android 14; CPH2493) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7221.215 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; CPH2493 Build/AP3A.240212.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7095.55 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; CPH2493 Build/AP3A.240502.902; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/138.0.6880.136 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; CPH2493 Build/AP3A.241070.169; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/121.0.6226.159 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; CTR-L91 Build/AP3A.240535.935; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/127.0.6785.172 Mobile Safari/537.36 TBS/470747 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 14; PFEM10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6192.152 Mobile Safari/537.36 HuaweiBrowser/16.0.78.259",
	"Mozilla/5.0 (Linux; Android 14; PFEM10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.7741.64 Mobile Safari/537.36 HuaweiBrowser/15.0.57.217",
	"Mozilla/5.0 (Linux; Android 14; PFEM10 Build/AP3A.240790.098; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.7301.204 Mobile Safari/537.36 TBS/478831 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 14; PFEM10 Build/AP3A.240926.772; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.7254.114 Mobile Safari/537.36 TBS/403756 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.7829.204 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP3A.240789.542; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/127.0.6231.94 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6404.197 Mobile Safari/537.36 HuaweiBrowser/15.0.68.300",
	"Mozilla/5.0 (Linux; Android 14; SM-S918B Build/AP3A.240386.376; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/139.0.6654.76 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; V2362A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6840.74 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; V2362A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6788.125 Mobile Safari/537.36 HuaweiBrowser/14.0.60.134",
	"Mozilla/5.0 (Linux; Android 15; 23113RKC6C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6450.134 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; CPH2493) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.6410.161 Mobile Safari/537.36 HuaweiBrowser/14.0.0.219",
	"Mozilla/5.0 (Linux; Android 15; CTR-L91) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6514.129 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; M2012K11AC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6331.82 Mobile Safari/537.36 HuaweiBrowser/14.0.3.126",
	"Mozilla/5.0 (Linux; Android 15; M2012K11AC Build/AP3A.240509.137; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/121.0.6017.114 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; PFEM10 Build/AP3A.240685.141; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.6978.200 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; Pixel 8 Build/AP3A.240228.981; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.7931.153 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.6165.98 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; SM-S918B Build/AP3A.240626.991; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/133.0.7160.180 Mobile Safari/537.36 TBS/425059 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 15; SM-S918B Build/AP3A.240925.181; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/137.0.7330.54 Mobile Safari/537.36 TBS/417306 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 15; V2362A Build/AP3A.240244.517; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/133.0.6137.46 Mobile Safari/537.36 TBS/453990 app_lang/zh-CN",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6050.61 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6859.177 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6371.42 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6798.94 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6914.61 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6244.145 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6648.82 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7_10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6250.106 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7_10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.7353.117 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7_10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6717.72 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7_10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.6799.97 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_7_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6638.207 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6990.113 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.7624.89 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.7916.73 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.6151.201 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.6730.174 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6860.64 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CNKI",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6875.180 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6359.46 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.7379.121 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6933.80 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.7367.154 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6350.190 Safari/537.36",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6236.120 Safari/537.36",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.7851.145 Safari/537.36",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.7780.52 Safari/537.36",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.7173.199 Safari/537.36",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.6315.177 Safari/537.36",
	"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6094.125 Safari/537.36",
	"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.7857.188 Safari/537.36",
	"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7389.112 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.7705.83 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6699.83 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.7476.179 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6533.179 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6323.115 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6026.171 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.7378.188 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6765.204 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.6558.155 Safari/537.36",
	"okhttp/4.12.0",

	/* ===== iOS 26 / Safari ===== */
	"Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/621.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/621.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 26_0_1 like Mac OS X) AppleWebKit/621.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/621.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 26_1 like Mac OS X) AppleWebKit/621.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/621.1",
	"Mozilla/5.0 (iPad; CPU OS 26_0 like Mac OS X) AppleWebKit/621.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/621.1",
	"Mozilla/5.0 (iPad; CPU OS 26_1 like Mac OS X) AppleWebKit/621.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/621.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/621.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/622.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 26_0_2 like Mac OS X) AppleWebKit/621.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/621.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 26_1_1 like Mac OS X) AppleWebKit/621.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/623.1",

	/* ===== 华为手机浏览器 HuaweiBrowser ===== */
	"Mozilla/5.0 (Linux; Android 14; HEX-AL09) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.136 Mobile Safari/537.36 HuaweiBrowser/15.0.4.302",
	"Mozilla/5.0 (Linux; Android 14; NOH-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.74 Mobile Safari/537.36 HuaweiBrowser/16.0.6.301",
	"Mozilla/5.0 (Linux; Android 14; BRP-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.100 Mobile Safari/537.36 HuaweiBrowser/16.0.44.301",
	"Mozilla/5.0 (Linux; Android 13; ELS-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.86 Mobile Safari/537.36 HuaweiBrowser/15.0.68.301",
	"Mozilla/5.0 (Linux; Android 13; LIO-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.127 Mobile Safari/537.36 HuaweiBrowser/15.0.4.301",
	"Mozilla/5.0 (Linux; Android 12; TAS-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36 HuaweiBrowser/14.0.6.301",
	"Mozilla/5.0 (Linux; Android 14; ALT-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.7151.55 Mobile Safari/537.36 HuaweiBrowser/16.0.78.301",
	"Mozilla/5.0 (Linux; Android 14; PCT-AL10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6917.108 Mobile Safari/537.36 HuaweiBrowser/15.0.68.302",
	"Mozilla/5.0 (Linux; Android 13; OCE-AN10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36 HuaweiBrowser/15.0.57.301",
	"Mozilla/5.0 (Linux; Android 12; JEF-AN20) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36 HuaweiBrowser/14.0.3.302",
	"Mozilla/5.0 (Linux; Android 14; CET-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.89 Mobile Safari/537.36 HuaweiBrowser/16.0.44.157",
	"Mozilla/5.0 (Linux; Android 14; NAM-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.125 Mobile Safari/537.36 HuaweiBrowser/16.0.6.192",
	"Mozilla/5.0 (Linux; Android 13; ANA-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Mobile Safari/537.36 HuaweiBrowser/15.0.4.126",
	"Mozilla/5.0 (Linux; Android 12; MED-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.179 Mobile Safari/537.36 HuaweiBrowser/14.0.60.134",
	"Mozilla/5.0 (Linux; Android 14; EBG-AN10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.7151.119 Mobile Safari/537.36 HuaweiBrowser/16.0.39.207",

	/* ===== OPPO 手机 ===== */
	"Mozilla/5.0 (Linux; Android 14; CPH2551) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.125 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; CPH2551 Build/AP3A.240812.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 TBS/420100 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 13; CPH2525) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.163 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; CPH2525 Build/AP3A.240617.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.6723.86 Mobile Safari/537.36 TBS/411033 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 14; CPH2609) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.7151.55 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; CPH2609 Build/AP3A.241010.045; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36 TBS/430886 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 12; CPH2385) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; CPH2449) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.260 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; CPH2631) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.157 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; CPH2449 Build/AP3A.240705.132; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.6613.127 Mobile Safari/537.36 TBS/398963 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 14; CPH2631 Build/AP3A.241010.135; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/136.0.7103.74 Mobile Safari/537.36 TBS/443756 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 12; CPH2385 Build/SP1A.210812.016; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/122.0.6261.105 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; CPH2691) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.89 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; CPH2691 Build/AP3A.241208.015; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/137.0.7151.119 Mobile Safari/537.36 TBS/453990 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 14; CPH2581) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.163 Mobile Safari/537.36",

	/* ===== 小米手机 ===== */
	"Mozilla/5.0 (Linux; Android 14; 2312DRN9AG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.74 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; 2312DRN9AG Build/AP3A.240812.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 TBS/420100 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 14; 23116PN5BC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.7151.55 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; 23116PN5BC Build/AP3A.241010.045; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36 TBS/430886 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 13; 2210132G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.86 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; 2210132G Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.6613.127 Mobile Safari/537.36 TBS/398963 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 14; 24031PN0DC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.89 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; 24031PN0DC Build/AP3A.241010.135; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/136.0.7103.125 Mobile Safari/537.36 TBS/443756 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 12; 21091116AI) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.179 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; 23013RK75C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; 2407FPN8EG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.7151.119 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; 2407FPN8EG Build/AP3A.241208.015; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/137.0.7151.55 Mobile Safari/537.36 TBS/453990 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 15; 24117RKC6G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.157 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; 24117RKC6G Build/AP3A.241208.015; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/138.0.7204.89 Mobile Safari/537.36 TBS/460123 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 13; 2209116AG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; M2012K11AC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.64 Mobile Safari/537.36",

	/* ===== 360 安全浏览器 ===== */
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.128 Safari/537.36 QIHU 360SE",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36 QIHU 360EE",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.84 Safari/537.36 QIHU 360SE",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.58 Safari/537.36 QIHU 360EE",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Safari/537.36 QIHU 360SE",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.83 Safari/537.36 QIHU 360EE",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.88 Safari/537.36 QIHU 360SE",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.140 Safari/537.36 QIHU 360SE",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.88 Safari/537.36 QIHU 360EE",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36 QIHU 360SE",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.48 Safari/537.36 QIHU 360EE",

	/* ===== iMac / MacBook M系列 (Apple Silicon) ===== */
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 15_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 14_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.165 Safari/537.36",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.93 Safari/537.36",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.7151.68 Safari/537.36",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.141 Safari/537.36",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.100 Safari/537.36",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 14_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.165 Safari/537.36 Edg/134.0.3124.85",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.93 Safari/537.36 Edg/136.0.3240.64",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 14_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.205 Safari/537.36",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 14_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.114 Safari/537.36",

	/* ===== 微信内置浏览器 (MicroMessenger) ===== */
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.54(0x1800362c) NetType/WIFI Language/zh_CN",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.55(0x1800371f) NetType/4G Language/zh_CN",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.53(0x18003527) NetType/WIFI Language/zh_CN",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_10 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.52(0x18003416) NetType/WIFI Language/zh_CN",
	"Mozilla/5.0 (Linux; Android 14; 2312DRN9AG Build/AP3A.240812.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 MicroMessenger/8.0.55.2780(0x28003757) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64",
	"Mozilla/5.0 (Linux; Android 14; NOH-AN00 Build/AP3A.240812.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 MicroMessenger/8.0.55.2780(0x28003757) WeChat/arm64 Weixin NetType/4G Language/zh_CN ABI/arm64",
	"Mozilla/5.0 (Linux; Android 13; CPH2525 Build/AP3A.240617.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.6723.86 Mobile Safari/537.36 MicroMessenger/8.0.54.2772(0x28003648) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64",
	"Mozilla/5.0 (Linux; Android 14; SM-S918B Build/AP3A.240386.376; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 MicroMessenger/8.0.55.2780(0x28003757) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64",
	"Mozilla/5.0 (Linux; Android 15; 24117RKC6G Build/AP3A.241208.015; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/137.0.7151.55 Mobile Safari/537.36 MicroMessenger/8.0.55.2780(0x28003757) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64",
	"Mozilla/5.0 (Macintosh; ARM Mac OS X 15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.165 Safari/537.36 MicroMessenger/6.8.0(0x16080000) MacWechat/3.8.9(0x13080912)",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143D) NetType/WIFI",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.54(0x1800362c) NetType/5G Language/zh_CN",
	"Mozilla/5.0 (Linux; Android 14; CPH2609 Build/AP3A.241010.045; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36 MicroMessenger/8.0.55.2780(0x28003757) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64",
	"Mozilla/5.0 (Linux; Android 13; ELS-AN00; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.6723.86 Mobile Safari/537.36 MicroMessenger/8.0.54.2772(0x28003648) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.55(0x1800371f) NetType/WIFI Language/zh_CN",

	/* ===== 三星 Samsung 手机 ===== */
	"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.125 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-S928B Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 TBS/420100 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 14; SM-A556B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.163 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.260 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6917.108 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/130.0.6723.86 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/136.0.7103.48 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.6167.143 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.89 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-F946B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.165 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; SM-A356B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.163 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/29.0 Chrome/138.0.7204.48 Mobile Safari/537.36",

	/* ===== vivo 手机 ===== */
	"Mozilla/5.0 (Linux; Android 14; V2329A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.74 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; V2329A Build/AP3A.240812.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 TBS/420100 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 13; V2249A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.86 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; V2411A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.7151.55 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; V2411A Build/AP3A.241010.045; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36 TBS/430886 app_lang/zh-CN",
	"Mozilla/5.0 (Linux; Android 15; V2503A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.89 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; V2144A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.179 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; V2248A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; V2408A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.125 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; V2408A Build/AP3A.241010.135; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/136.0.7103.74 Mobile Safari/537.36 TBS/443756 app_lang/zh-CN",

	/* ===== 抖音/TikTok App 内置浏览器 ===== */
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 musical_ly/350103 JsSdk/2.0 NetType/WIFI Channel/App Store ByteLocale/zh-CN ByteFullLocale/zh-CN Region/CN",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 musical_ly/360102 JsSdk/2.0 NetType/4G Channel/App Store ByteLocale/zh-CN ByteFullLocale/zh-CN Region/CN",
	"Mozilla/5.0 (Linux; Android 14; 2312DRN9AG Build/AP3A.240812.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 musical_ly/350103 JsSdk/2.0 NetType/WIFI Channel/googleplay ByteLocale/zh-CN Region/CN",
	"Mozilla/5.0 (Linux; Android 14; NOH-AN00 Build/AP3A.240812.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 musical_ly/360102 JsSdk/2.0 NetType/5G Channel/huawei ByteLocale/zh-CN Region/CN",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 musical_ly/340105 JsSdk/2.0 NetType/WIFI Channel/App Store ByteLocale/zh-CN Region/CN",
	"Mozilla/5.0 (Linux; Android 13; CPH2525 Build/AP3A.240617.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.6723.86 Mobile Safari/537.36 musical_ly/350103 JsSdk/2.0 NetType/WIFI Channel/oppo ByteLocale/zh-CN Region/CN",

	/* ===== 支付宝 App 内置浏览器 ===== */
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 AlipayClient/10.5.60.6000 Language/zh-Hans Region/CN",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 AlipayClient/10.5.62.8000 Language/zh-Hans Region/CN",
	"Mozilla/5.0 (Linux; Android 14; 2312DRN9AG Build/AP3A.240812.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 AlipayClient/10.5.60.6000 Language/zh-Hans Region/CN",
	"Mozilla/5.0 (Linux; Android 14; NOH-AN00 Build/AP3A.240812.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 AlipayClient/10.5.62.8000 Language/zh-Hans Region/CN",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 AlipayClient/10.5.58.4000 Language/zh-Hans Region/CN",
	"Mozilla/5.0 (Linux; Android 13; CPH2525 Build/AP3A.240617.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.6723.86 Mobile Safari/537.36 AlipayClient/10.5.60.6000 Language/zh-Hans Region/CN",

	/* ===== Windows Edge 浏览器 ===== */
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.165 Safari/537.36 Edg/134.0.3124.85",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.93 Safari/537.36 Edg/136.0.3240.64",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.100 Safari/537.36 Edg/138.0.3351.54",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.205 Safari/537.36 Edg/131.0.2903.112",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.141 Safari/537.36 Edg/133.0.3065.92",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.114 Safari/537.36 Edg/135.0.3179.73",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.7151.68 Safari/537.36 Edg/137.0.3296.52",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.58 Safari/537.36 Edg/130.0.2849.52",

};

const char *garble_http_random_user_agent(void)
{
	return http_user_agents[prandom_u32() % ARRAY_SIZE(http_user_agents)];
}

unsigned char *build_http_request(unsigned char *buf, int *len, const char *host)
{
	int len_;
	const char *method = http_methods[prandom_u32() % ARRAY_SIZE(http_methods)];
	const char *path = http_paths[prandom_u32() % ARRAY_SIZE(http_paths)];
	const char *ua = garble_http_random_user_agent();

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
