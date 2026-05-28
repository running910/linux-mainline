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

inline unsigned char *build_http_download_request(unsigned char *buf, int *len,
						  const char *host)
{
	char path[128];
	int len_;
	const char *ua = http_user_agents[prandom_u32() % ARRAY_SIZE(http_user_agents)];
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

struct http_search_template {
	const char *host;
	const char *path_fmt;
	const char *referer_fmt;
	unsigned int header_profile;
	const char * const *keywords;
	unsigned int keyword_count;
	const char * const *extra;
	unsigned int extra_count;
};

enum http_search_header_profile {
	HTTP_SEARCH_HEADER_TIEBA,
	HTTP_SEARCH_HEADER_DEEPSEEK_SCHOLAR,
	HTTP_SEARCH_HEADER_DEEPSEEK_KNS,
	HTTP_SEARCH_HEADER_ICOURSE163,
	HTTP_SEARCH_HEADER_KEQQ,
	HTTP_SEARCH_HEADER_XHS,
	HTTP_SEARCH_HEADER_XIMALAYA,
	HTTP_SEARCH_HEADER_OPEN163,
	HTTP_SEARCH_HEADER_IMOOC,
};

enum http_search_template_id {
	HTTP_SEARCH_TEMPLATE_TIEBA,
	HTTP_SEARCH_TEMPLATE_C_TIEBA,
	HTTP_SEARCH_TEMPLATE_DEEPSEEK_SCHOLAR,
	HTTP_SEARCH_TEMPLATE_DEEPSEEK_KNS,
	HTTP_SEARCH_TEMPLATE_ICOURSE163,
	HTTP_SEARCH_TEMPLATE_MOOC_STUDY_163,
	HTTP_SEARCH_TEMPLATE_KE_QQ,
	HTTP_SEARCH_TEMPLATE_H5_KE_QQ,
	HTTP_SEARCH_TEMPLATE_XHS_WWW,
	HTTP_SEARCH_TEMPLATE_XHS_API,
	HTTP_SEARCH_TEMPLATE_XHS_CREATOR,
	HTTP_SEARCH_TEMPLATE_XIMALAYA_MOBILE,
	HTTP_SEARCH_TEMPLATE_XIMALAYA_API,
	HTTP_SEARCH_TEMPLATE_OPEN_163,
	HTTP_SEARCH_TEMPLATE_VOD_OPEN_163,
	HTTP_SEARCH_TEMPLATE_IMOOC,
	HTTP_SEARCH_TEMPLATE_CODING_IMOOC,

	HTTP_SEARCH_TEMPLATE_MAX
};

static const char * const http_search_tieba_keywords[] = {
	"原神",
	"英雄联盟",
	"王者荣耀",
	"阴阳师",
	"魔兽世界",
	"绝地求生",
	"和平精英",
	"崩坏",
	"星穹铁道",
	"穿越火线",
	"地下城与勇士",
	"梦幻西游",
	"炉石传说",
	"明日方舟",
	"第五人格",
	"三国杀",
	"逆水寒",
	"剑网三",
	"房产",
	"旅游",
	"美食",
	"摄影",
	"音乐",
	"电影",
	"汽车",
	"装修",
	"数码",
	"宠物",
	"健身",
	"篮球",
	"足球",
	"考研",
	"公务员",
	"股票",
	"基金",
	"二手房",
	"租房",
	"露营",
	"骑行",
	"动漫",
	"小说",
	"电视剧",
	"综艺",
	"手游",
	"主机游戏",
	"单机游戏",
	"电竞",
	"数码相机",
	"手机",
	"电脑",
	"笔记本",
	"机械键盘",
	"耳机",
	"显卡",
	"新能源车",
	"摩托车",
	"钓鱼",
	"跑步",
	"羽毛球",
	"乒乓球",
	"网球",
	"游泳",
	"瑜伽",
	"减肥",
	"护肤",
	"化妆",
	"穿搭",
	"家居",
	"园艺",
	"猫",
	"狗",
	"留学",
	"英语",
	"高考",
	"中考",
	"教师资格证",
	"事业单位",
	"银行招聘",
	"创业",
	"副业",
	"职场",
	"面试",
	"简历",
	"理财",
	"保险",
	"楼市",
	"装修日记",
	"母婴",
	"育儿",
	"婚礼",
	"相亲",
	"大学",
	"校园",
	"城市规划",
	"北京",
	"上海",
	"广州",
	"深圳",
	"成都",
	"杭州",
};

static const char * const http_search_scholar_keywords[] = {
	"人工智能",
	"深度学习",
	"自然语言处理",
	"计算机视觉",
	"神经网络",
	"推荐系统",
	"强化学习",
	"软件工程",
	"边缘计算",
	"知识图谱",
	"机器学习",
	"目标检测",
	"语音识别",
	"模式识别",
	"数据库设计",
	"大数据分析",
	"云计算",
	"信息安全",
	"网络协议",
	"无线通信",
	"数字信号处理",
	"分布式系统",
	"区块链",
	"联邦学习",
	"图神经网络",
	"多模态学习",
	"数据挖掘",
	"隐私计算",
	"智能推荐",
	"自动驾驶",
	"医学影像",
	"异常检测",
	"密码学",
	"操作系统",
	"编译原理",
	"计算广告",
	"强化学习算法",
	"大语言模型",
	"视觉问答",
	"迁移学习",
	"半监督学习",
	"无监督学习",
	"对比学习",
	"预训练模型",
	"生成对抗网络",
	"扩散模型",
	"图像分割",
	"人脸识别",
	"行人重识别",
	"视频理解",
	"三维重建",
	"点云处理",
	"语义分割",
	"机器翻译",
	"文本分类",
	"情感分析",
	"信息抽取",
	"问答系统",
	"对话系统",
	"语音合成",
	"说话人识别",
	"推荐算法",
	"协同过滤",
	"点击率预估",
	"时间序列预测",
	"异常检测算法",
	"因果推断",
	"可解释人工智能",
	"模型压缩",
	"知识蒸馏",
	"边缘智能",
	"物联网安全",
	"软件定义网络",
	"网络测量",
	"拥塞控制",
	"路由算法",
	"云原生",
	"容器调度",
	"微服务架构",
	"服务网格",
	"数据库系统",
	"事务处理",
	"查询优化",
	"分布式存储",
	"一致性协议",
	"拜占庭容错",
	"隐私保护",
	"同态加密",
	"安全多方计算",
	"入侵检测",
	"恶意代码检测",
	"漏洞挖掘",
	"程序分析",
	"智能合约",
	"量子计算",
	"计算机体系结构",
	"高性能计算",
	"并行计算",
	"人机交互",
	"增强现实",
};

static const char * const http_search_kns_keywords[] = {
	"学术论文",
	"文献综述",
	"研究方法",
	"统计分析",
	"理论框架",
	"假设检验",
	"变量测量",
	"文献检索",
	"学术写作",
	"研究设计",
	"学术规范",
	"学术贡献",
	"引用格式",
	"案例分析",
	"实证研究",
	"定量研究",
	"定性研究",
	"问卷设计",
	"样本选择",
	"数据分析",
	"概念模型",
	"理论研究",
	"理论基础",
	"知识体系",
	"研究伦理",
	"研究假设",
	"结构方程",
	"回归分析",
	"中介效应",
	"调节效应",
	"信度效度",
	"变量定义",
	"量表开发",
	"论文选题",
	"开题报告",
	"研究背景",
	"研究意义",
	"国内外研究",
	"参考文献",
	"研究问题",
	"研究目标",
	"研究内容",
	"创新点",
	"理论意义",
	"实践意义",
	"文献计量",
	"系统综述",
	"元分析",
	"扎根理论",
	"访谈法",
	"观察法",
	"实验设计",
	"准实验研究",
	"横断面研究",
	"纵向研究",
	"混合研究",
	"内容分析",
	"文本分析",
	"扎根编码",
	"量化分析",
	"描述性统计",
	"相关分析",
	"方差分析",
	"主成分分析",
	"因子分析",
	"聚类分析",
	"判别分析",
	"时间序列",
	"面板数据",
	"稳健性检验",
	"异质性分析",
	"内生性问题",
	"工具变量",
	"双重差分",
	"倾向得分匹配",
	"事件研究法",
	"路径分析",
	"结构模型",
	"变量关系",
	"理论模型",
	"概念界定",
	"操作化定义",
	"测量指标",
	"评价体系",
	"指标体系",
	"问卷信度",
	"效度检验",
	"样本容量",
	"抽样方法",
	"数据来源",
	"数据清洗",
	"编码规则",
	"论文摘要",
	"论文结论",
	"研究局限",
	"未来展望",
	"投稿经验",
	"期刊选择",
	"论文查重",
	"答辩准备",
};

static const char * const http_search_course_keywords[] = {
	"Python",
	"Java",
	"算法",
	"前端开发",
	"产品经理",
	"会计",
	"考研英语",
	"公务员",
	"教师资格证",
	"英语四级",
	"英语六级",
	"雅思",
	"托福",
	"高等数学",
	"数据分析",
	"机器学习",
	"深度学习",
	"人工智能",
	"大数据",
	"云计算",
	"网络安全",
	"软件测试",
	"数据库",
	"Linux",
	"Go语言",
	"C++",
	"设计",
	"平面设计",
	"UI设计",
	"短视频运营",
	"电商运营",
	"市场营销",
	"财务管理",
	"心理学",
	"注册会计师",
	"初级会计",
	"中级会计",
	"税务师",
	"法考",
	"建造师",
	"消防工程师",
	"护士资格证",
	"医学考研",
	"日语",
	"韩语",
	"德语",
	"法语",
	"西班牙语",
	"少儿英语",
	"商务英语",
	"口语",
	"听力",
	"写作",
	"Excel",
	"PPT",
	"办公软件",
	"项目管理",
	"PMP",
	"人力资源",
	"运营管理",
	"新媒体运营",
	"直播运营",
	"私域运营",
	"剪辑",
	"摄影",
	"视频制作",
	"插画",
	"室内设计",
	"建筑设计",
	"服装设计",
	"电商设计",
	"品牌策划",
	"销售技巧",
	"谈判技巧",
	"职场沟通",
	"领导力",
	"时间管理",
	"思维导图",
	"家庭教育",
	"亲子沟通",
	"儿童编程",
	"Scratch",
	"机器人编程",
	"数学思维",
	"高中数学",
	"高中物理",
	"高中化学",
	"初中英语",
	"考研数学",
	"考研政治",
	"考研专业课",
	"金融学",
	"经济学",
	"统计学",
	"供应链管理",
	"跨境电商",
	"亚马逊运营",
	"淘宝运营",
	"短视频剪辑",
	"直播带货",
};

static const char * const http_search_mooc_keywords[] = {
	"C语言程序设计",
	"Python程序设计",
	"数据结构",
	"数据库系统",
	"计算机网络",
	"操作系统",
	"高等数学",
	"大学英语",
	"线性代数",
	"概率论",
	"离散数学",
	"计算机组成原理",
	"编译原理",
	"软件工程",
	"人工智能",
	"机器学习",
	"深度学习",
	"算法设计",
	"数据挖掘",
	"信息安全",
	"网络技术",
	"数字信号处理",
	"通信原理",
	"电路原理",
	"模拟电子技术",
	"数字电子技术",
	"大学物理",
	"工程力学",
	"管理学",
	"经济学原理",
	"心理学导论",
	"中国近现代史",
	"马克思主义基本原理",
	"大学语文",
	"大学化学",
	"生物化学",
	"普通生物学",
	"遗传学",
	"细胞生物学",
	"医学统计学",
	"流行病学",
	"组织行为学",
	"市场营销学",
	"财务管理",
	"会计学原理",
	"金融学",
	"国际贸易",
	"电子商务",
	"供应链管理",
	"项目管理",
	"创业管理",
	"社会学概论",
	"法学导论",
	"民法学",
	"刑法学",
	"教育学",
	"现代汉语",
	"古代文学",
	"英语写作",
	"英语口语",
	"日语入门",
	"艺术概论",
	"音乐鉴赏",
	"美术鉴赏",
	"影视鉴赏",
	"机器视觉",
	"机器人学",
	"自动控制原理",
	"信号与系统",
	"电磁场",
	"微机原理",
	"嵌入式系统",
	"物联网技术",
	"云计算技术",
	"区块链技术",
	"网络安全",
	"密码学",
	"数据库原理",
	"Web开发",
	"移动应用开发",
	"自然语言处理",
	"计算机图形学",
	"数字图像处理",
	"运筹学",
	"数值分析",
	"复变函数",
	"数学建模",
	"环境科学",
	"土木工程概论",
	"机械设计基础",
	"材料科学基础",
	"能源与动力工程",
	"食品科学导论",
	"公共卫生",
	"伦理学",
	"逻辑学",
	"创新创业",
	"职业发展",
	"学术英语",
	"科研方法",
};

static const char * const http_search_xhs_keywords[] = {
	"口红",
	"面膜",
	"眼霜",
	"洁面",
	"探店",
	"滑雪",
	"跑步",
	"瑜伽",
	"机器学习",
	"深度学习",
	"房产",
	"西餐",
	"穿搭",
	"外套",
	"连衣裙",
	"项链",
	"香水",
	"防晒",
	"去角质",
	"爽肤水",
	"粉底液",
	"护发",
	"美甲",
	"烘焙",
	"咖啡",
	"露营",
	"骑行",
	"拳击",
	"滑板",
	"健身餐",
	"装修",
	"家居",
	"收纳",
	"深圳",
	"广州",
	"南京",
	"西安",
	"亲子游",
	"周末去哪",
	"考研",
	"英语学习",
	"摄影教程",
	"数码好物",
	"平价彩妆",
	"护肤空瓶",
	"敏感肌",
	"油皮护肤",
	"干皮护肤",
	"早八妆",
	"通勤穿搭",
	"法式穿搭",
	"小个子穿搭",
	"显瘦穿搭",
	"秋冬穿搭",
	"夏日穿搭",
	"运动鞋",
	"帆布鞋",
	"包包",
	"耳饰",
	"戒指",
	"手表",
	"香薰",
	"家居好物",
	"租房改造",
	"厨房收纳",
	"卧室布置",
	"客厅装修",
	"猫咪用品",
	"狗狗用品",
	"减脂餐",
	"低卡零食",
	"早餐",
	"下午茶",
	"火锅",
	"日料",
	"咖啡店",
	"民宿",
	"Citywalk",
	"周边游",
	"海岛旅行",
	"徒步",
	"滑雪装备",
	"普拉提",
	"羽毛球",
	"马拉松",
	"书单",
	"自律打卡",
	"学习方法",
	"留学申请",
	"雅思备考",
	"考公",
	"面试经验",
	"简历修改",
	"副业赚钱",
	"职场穿搭",
	"办公桌面",
	"iPad学习",
	"MacBook",
	"相机推荐",
	"手机摄影",
};

static const char * const http_search_xhs_sorts[] = {
	"general",
	"popularity",
	"time",
	"rating",
	"price_asc",
	"price_desc",
	"distance",
};

static const char * const http_search_ximalaya_keywords[] = {
	"睡前故事",
	"儿童故事",
	"英语听力",
	"郭德纲",
	"财经早报",
	"心理学",
	"人文历史",
	"科技Talk",
	"有声小说",
	"悬疑故事",
	"历史故事",
	"商业财经",
	"投资理财",
	"每日新闻",
	"亲子教育",
	"国学经典",
	"相声评书",
	"脱口秀",
	"健康养生",
	"职场提升",
	"考研英语",
	"雅思听力",
	"儿童英语",
	"白噪音",
	"冥想音乐",
	"睡眠音乐",
	"汽车电台",
	"科技新闻",
	"电影解说",
	"读书会",
	"都市小说",
	"玄幻小说",
	"武侠小说",
	"言情小说",
	"科幻小说",
	"推理小说",
	"睡前音乐",
	"轻音乐",
	"古典音乐",
	"钢琴曲",
	"英语口语",
	"英语单词",
	"日语学习",
	"法语入门",
	"考研政治",
	"考研数学",
	"公务员考试",
	"事业单位考试",
	"教师资格证",
	"育儿百科",
	"家庭教育",
	"绘本故事",
	"成语故事",
	"西游记",
	"三国演义",
	"红楼梦",
	"水浒传",
	"明朝那些事儿",
	"世界历史",
	"中国历史",
	"人物传记",
	"商业案例",
	"管理学",
	"经济学",
	"股票入门",
	"基金投资",
	"保险知识",
	"房产投资",
	"创业故事",
	"个人成长",
	"沟通技巧",
	"时间管理",
	"情绪管理",
	"心理咨询",
	"健康科普",
	"中医养生",
	"瑜伽冥想",
	"新闻早餐",
	"科技前沿",
	"互联网观察",
	"汽车评测",
	"游戏电台",
	"体育新闻",
	"篮球评论",
	"足球故事",
	"电影原声",
	"粤语歌",
	"流行音乐",
	"播客",
	"脱口秀大会",
	"评书联播",
	"亲子故事",
	"胎教音乐",
	"儿童科普",
	"自然百科",
	"地理知识",
	"法律常识",
	"职场英语",
	"睡眠冥想",
	"白噪声",
};

static const char * const http_search_open163_keywords[] = {
	"TED",
	"历史",
	"斯坦福",
	"生物学",
	"公开课",
	"哈佛",
	"耶鲁",
	"麻省理工",
	"心理学",
	"经济学",
	"哲学",
	"文学",
	"艺术史",
	"计算机科学",
	"人工智能",
	"数据科学",
	"物理学",
	"化学",
	"医学",
	"金融学",
	"创业",
	"管理学",
	"演讲",
	"纪录片",
	"中国大学视频公开课",
	"可汗学院",
	"英语演讲",
	"牛津",
	"剑桥",
	"普林斯顿",
	"伯克利",
	"哥伦比亚大学",
	"芝加哥大学",
	"公开演讲",
	"人文社科",
	"社会学",
	"政治学",
	"国际关系",
	"法学",
	"教育学",
	"语言学",
	"心理健康",
	"认知科学",
	"神经科学",
	"天文学",
	"宇宙学",
	"地球科学",
	"环境科学",
	"气候变化",
	"生命科学",
	"遗传学",
	"医学公开课",
	"公共卫生",
	"营养学",
	"建筑学",
	"城市规划",
	"设计思维",
	"音乐欣赏",
	"电影艺术",
	"摄影艺术",
	"西方艺术史",
	"中国历史",
	"世界历史",
	"古希腊文明",
	"罗马史",
	"现代文学",
	"莎士比亚",
	"人工智能伦理",
	"机器学习",
	"深度学习",
	"编程入门",
	"数据分析",
	"统计学",
	"微积分",
	"线性代数",
	"博弈论",
	"金融市场",
	"宏观经济学",
	"微观经济学",
	"市场营销",
	"领导力",
	"创新管理",
	"创业课程",
	"幸福课",
	"批判性思维",
	"英语听力",
	"英语写作",
	"公开课字幕",
	"名校课程",
	"诺贝尔奖",
	"科学史",
	"TED演讲",
	"纪录片解说",
	"通识教育",
	"在线课程",
	"大学课程",
	"学术讲座",
	"人类学",
	"宗教学",
	"生态学",
};

static const char * const http_search_imooc_keywords[] = {
	"MySQL",
	"Python",
	"Linux",
	"C++",
	"算法",
	"人工智能",
	"前端",
	"Java",
	"Spring Boot",
	"Vue",
	"React",
	"Node.js",
	"Go语言",
	"PHP",
	"Redis",
	"MongoDB",
	"Docker",
	"Kubernetes",
	"微服务",
	"分布式",
	"数据结构",
	"大数据",
	"Hadoop",
	"Spark",
	"机器学习",
	"深度学习",
	"自动化测试",
	"性能优化",
	"网络安全",
	"移动开发",
	"Android",
	"iOS",
	"小程序",
	"前端工程化",
	"TypeScript",
	"Webpack",
	"Vite",
	"Next.js",
	"Nuxt",
	"Flutter",
	"鸿蒙开发",
	"Swift",
	"Kotlin",
	"Rust",
	"Python爬虫",
	"Django",
	"Flask",
	"FastAPI",
	"Java并发",
	"JVM",
	"MyBatis",
	"Spring Cloud",
	"Dubbo",
	"消息队列",
	"Kafka",
	"RabbitMQ",
	"Elasticsearch",
	"ClickHouse",
	"PostgreSQL",
	"数据库优化",
	"SQL调优",
	"架构设计",
	"高并发",
	"高可用",
	"缓存",
	"负载均衡",
	"DevOps",
	"CI/CD",
	"Linux运维",
	"Nginx",
	"云服务器",
	"Serverless",
	"Prometheus",
	"Grafana",
	"日志系统",
	"数据仓库",
	"数据湖",
	"Flink",
	"推荐系统",
	"自然语言处理",
	"计算机视觉",
	"大模型",
	"Prompt工程",
	"机器学习实战",
	"深度学习框架",
	"PyTorch",
	"TensorFlow",
	"OpenCV",
	"接口测试",
	"单元测试",
	"安全攻防",
	"渗透测试",
	"区块链",
	"智能合约",
	"Web3",
	"低代码",
	"程序员面试",
	"算法刷题",
	"系统设计",
	"代码重构",
};

static const char * const http_search_course_mts[] = {
	"it",
	"exam",
	"k12",
	"design",
	"language",
	"postgraduate",
};

static const struct http_search_template http_search_templates[HTTP_SEARCH_TEMPLATE_MAX] = {
	[HTTP_SEARCH_TEMPLATE_TIEBA] = { "tieba.baidu.com", "/f?kw=%s&pn=%u", "https://tieba.baidu.com/", HTTP_SEARCH_HEADER_TIEBA, http_search_tieba_keywords, ARRAY_SIZE(http_search_tieba_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_C_TIEBA] = { "c.tieba.baidu.com", "/f?kw=%s&pn=%u", "https://tieba.baidu.com/", HTTP_SEARCH_HEADER_TIEBA, http_search_tieba_keywords, ARRAY_SIZE(http_search_tieba_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_DEEPSEEK_SCHOLAR] = { "www.deepseek.com", "/scholar?q=%s&start=%u&tn=scholar", "https://scholar.baidu.com/", HTTP_SEARCH_HEADER_DEEPSEEK_SCHOLAR, http_search_scholar_keywords, ARRAY_SIZE(http_search_scholar_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_DEEPSEEK_KNS] = { "www.deepseek.com", "/kns/brief/result.aspx?dbprefix=CFLS&keyValue=%s&page=%u", "https://www.deepseek.com/", HTTP_SEARCH_HEADER_DEEPSEEK_KNS, http_search_kns_keywords, ARRAY_SIZE(http_search_kns_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_ICOURSE163] = { "www.icourse163.org", "/search.htm?search=%s", "https://www.icourse163.org/", HTTP_SEARCH_HEADER_ICOURSE163, http_search_mooc_keywords, ARRAY_SIZE(http_search_mooc_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_MOOC_STUDY_163] = { "mooc.study.163.com", "/search.htm?search=%s", "https://www.icourse163.org/", HTTP_SEARCH_HEADER_ICOURSE163, http_search_mooc_keywords, ARRAY_SIZE(http_search_mooc_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_KE_QQ] = { "ke.qq.com", "/cgi-bin/search?keyword=%s&page=%u", "https://ke.qq.com/", HTTP_SEARCH_HEADER_KEQQ, http_search_course_keywords, ARRAY_SIZE(http_search_course_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_H5_KE_QQ] = { "h5.ke.qq.com", "/cgi-bin/course_list?mt=%s&page=%u&keyword=%s", "https://ke.qq.com/", HTTP_SEARCH_HEADER_KEQQ, http_search_course_keywords, ARRAY_SIZE(http_search_course_keywords), http_search_course_mts, ARRAY_SIZE(http_search_course_mts) },
	[HTTP_SEARCH_TEMPLATE_XHS_WWW] = { "www.xiaohongshu.com", "/api/sns/v3/search/note?keyword=%s&sort=%s&page=1&size=20", "https://www.xiaohongshu.com/", HTTP_SEARCH_HEADER_XHS, http_search_xhs_keywords, ARRAY_SIZE(http_search_xhs_keywords), http_search_xhs_sorts, ARRAY_SIZE(http_search_xhs_sorts) },
	[HTTP_SEARCH_TEMPLATE_XHS_API] = { "api.xiaohongshu.com", "/api/sns/v3/search/note?keyword=%s&sort=%s&page=1&size=20", "https://www.xiaohongshu.com/", HTTP_SEARCH_HEADER_XHS, http_search_xhs_keywords, ARRAY_SIZE(http_search_xhs_keywords), http_search_xhs_sorts, ARRAY_SIZE(http_search_xhs_sorts) },
	[HTTP_SEARCH_TEMPLATE_XHS_CREATOR] = { "creator.xiaohongshu.com", "/api/sns/v3/search/note?keyword=%s&sort=%s&page=1&size=20", "https://www.xiaohongshu.com/", HTTP_SEARCH_HEADER_XHS, http_search_xhs_keywords, ARRAY_SIZE(http_search_xhs_keywords), http_search_xhs_sorts, ARRAY_SIZE(http_search_xhs_sorts) },
	[HTTP_SEARCH_TEMPLATE_XIMALAYA_MOBILE] = { "mobile.ximalaya.com", "/search/%s/?page=%u", "https://www.ximalaya.com/", HTTP_SEARCH_HEADER_XIMALAYA, http_search_ximalaya_keywords, ARRAY_SIZE(http_search_ximalaya_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_XIMALAYA_API] = { "api.ximalaya.com", "/search/%s/?page=%u", "https://www.ximalaya.com/", HTTP_SEARCH_HEADER_XIMALAYA, http_search_ximalaya_keywords, ARRAY_SIZE(http_search_ximalaya_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_OPEN_163] = { "open.163.com", "/search/search.htm?query=%s&page=%u", "https://open.163.com/", HTTP_SEARCH_HEADER_OPEN163, http_search_open163_keywords, ARRAY_SIZE(http_search_open163_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_VOD_OPEN_163] = { "vod.open.163.com", "/search/search.htm?query=%s&page=%u", "https://open.163.com/", HTTP_SEARCH_HEADER_OPEN163, http_search_open163_keywords, ARRAY_SIZE(http_search_open163_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_IMOOC] = { "www.imooc.com", "/search/?words=%s&page=%u", "https://www.imooc.com/", HTTP_SEARCH_HEADER_IMOOC, http_search_imooc_keywords, ARRAY_SIZE(http_search_imooc_keywords), NULL, 0 },
	[HTTP_SEARCH_TEMPLATE_CODING_IMOOC] = { "coding.imooc.com", "/search/?words=%s&page=%u", "https://www.imooc.com/", HTTP_SEARCH_HEADER_IMOOC, http_search_imooc_keywords, ARRAY_SIZE(http_search_imooc_keywords), NULL, 0 },
};

static const char * const http_search_accepts[] = {
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"application/json,text/plain,*/*",
	"text/html,*/*;q=0.8",
};

static const char * const http_search_languages[] = {
	"zh-CN,zh;q=0.9",
	"zh-CN,zh;q=0.9,en;q=0.8",
	"en-US,en;q=0.9,zh-CN;q=0.8",
};

static const char * const http_search_connections[] = {
	"keep-alive",
	"close",
};

static int build_http_search_cookie(char *buf, size_t size,
				    unsigned int profile)
{
	u32 a = prandom_u32();
	u32 b = prandom_u32();
	u32 c = prandom_u32();
	u32 d = prandom_u32();

	switch (profile) {
	case HTTP_SEARCH_HEADER_DEEPSEEK_SCHOLAR:
		return snprintf(buf, size,
			"Cookie: _ttp=%08x%08x; msToken=%08x; "
			"BDUSS=%08x%08x; SESSIONID=%08x%08x\r\n",
			a, b, c, b, d, c, a);
	case HTTP_SEARCH_HEADER_DEEPSEEK_KNS:
		return snprintf(buf, size,
			"Cookie: sessionid=%08x-%08x; "
			"CnkiUserName=%08x%08x; CnkiOrgCode=%08x%08x; "
			"CnkiSessionId=%08x%08x\r\n",
			a, b, b, c, c, d, d, a);
	case HTTP_SEARCH_HEADER_KEQQ:
		return snprintf(buf, size,
			"Cookie: sid=%08x%08x; auth_token=%08x%08x; "
			"request_id=%08x\r\n",
			a, b, c, d, a ^ c);
	case HTTP_SEARCH_HEADER_XIMALAYA:
	case HTTP_SEARCH_HEADER_OPEN163:
	case HTTP_SEARCH_HEADER_IMOOC:
		return snprintf(buf, size,
			"Cookie: sessionid=%08x%08x; correlation_id=%08x%08x\r\n",
			a, b, c, d);
	default:
		buf[0] = '\0';
		return 0;
	}
}

inline unsigned char *build_http_search_request_by_template(unsigned char *buf,
							    int *len,
							    int template_id)
{
	char path[256];
	char referer_header[288] = "";
	char cookie_header[384] = "";
	char fetch_headers[192] = "";
	char cache_header[32] = "";
	int len_;
	const char *accept;
	const char *accept_language = "zh-CN,zh;q=0.9,en;q=0.8";
	const char *connection = "keep-alive";
	const struct http_search_template *tpl;
	const char *keyword;
	const char *extra;
	const char *ua;
	u32 page;

	if (template_id < 0)
		template_id = prandom_u32() % HTTP_SEARCH_TEMPLATE_MAX;
	if (template_id >= HTTP_SEARCH_TEMPLATE_MAX)
		return NULL;

	tpl = &http_search_templates[template_id];
	if (!tpl->host || !tpl->path_fmt || !tpl->keywords || !tpl->keyword_count)
		return NULL;

	keyword = tpl->keywords[prandom_u32() % tpl->keyword_count];
	extra = tpl->extra_count ? tpl->extra[prandom_u32() % tpl->extra_count] : NULL;
	ua = http_user_agents[prandom_u32() % ARRAY_SIZE(http_user_agents)];
	accept = http_search_accepts[prandom_u32() % ARRAY_SIZE(http_search_accepts)];

	if (strstr(tpl->path_fmt, "start=%u"))
		page = (prandom_u32() % 10) * 10;
	else if (strstr(tpl->path_fmt, "pn=%u"))
		page = (prandom_u32() % 10) * 50;
	else
		page = (prandom_u32() % 20) + 1;

	if (extra && strstr(tpl->path_fmt, "mt=%s"))
		len_ = snprintf(path, sizeof(path), tpl->path_fmt,
				extra, page, keyword);
	else if (extra)
		len_ = snprintf(path, sizeof(path), tpl->path_fmt,
				keyword, extra);
	else if (strstr(tpl->path_fmt, "%u"))
		len_ = snprintf(path, sizeof(path), tpl->path_fmt,
				keyword, page);
	else
		len_ = snprintf(path, sizeof(path), tpl->path_fmt,
				keyword);

	if (len_ < 0 || len_ >= (int)sizeof(path)) {
		printk("ERROR: http search path is too long");
		return buf;
	}

	if (tpl->referer_fmt) {
		len_ = snprintf(referer_header, sizeof(referer_header),
				"Referer: %s\r\n", tpl->referer_fmt);
		if (len_ < 0 || len_ >= (int)sizeof(referer_header)) {
			printk("ERROR: http search referer header is too long");
			return buf;
		}
	}

	switch (tpl->header_profile) {
	case HTTP_SEARCH_HEADER_DEEPSEEK_SCHOLAR:
		accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8";
		snprintf(fetch_headers, sizeof(fetch_headers),
			 "Sec-Fetch-Dest: document\r\n"
			 "Sec-Fetch-Mode: navigate\r\n"
			 "Sec-Fetch-Site: same-origin\r\n"
			 "Sec-Fetch-User: ?1\r\n"
			 "Upgrade-Insecure-Requests: 1\r\n");
		snprintf(cache_header, sizeof(cache_header),
			 "Cache-Control: max-age=0\r\n");
		break;
	case HTTP_SEARCH_HEADER_DEEPSEEK_KNS:
		accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8";
		snprintf(fetch_headers, sizeof(fetch_headers),
			 "Sec-Fetch-Dest: document\r\n"
			 "Sec-Fetch-Mode: navigate\r\n"
			 "Sec-Fetch-Site: same-origin\r\n"
			 "Sec-Fetch-User: ?1\r\n"
			 "Upgrade-Insecure-Requests: 1\r\n");
		snprintf(cache_header, sizeof(cache_header),
			 "Cache-Control: max-age=0\r\n");
		break;
	case HTTP_SEARCH_HEADER_XHS:
		accept = "application/json, text/plain, */*";
		break;
	case HTTP_SEARCH_HEADER_TIEBA:
	case HTTP_SEARCH_HEADER_ICOURSE163:
		accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
		break;
	case HTTP_SEARCH_HEADER_KEQQ:
	case HTTP_SEARCH_HEADER_XIMALAYA:
	case HTTP_SEARCH_HEADER_OPEN163:
	case HTTP_SEARCH_HEADER_IMOOC:
		accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
		break;
	default:
		break;
	}

	if (tpl->header_profile != HTTP_SEARCH_HEADER_TIEBA &&
	    tpl->header_profile != HTTP_SEARCH_HEADER_ICOURSE163 &&
	    tpl->header_profile != HTTP_SEARCH_HEADER_XHS) {
		len_ = build_http_search_cookie(cookie_header,
						sizeof(cookie_header),
						tpl->header_profile);
		if (len_ < 0 || len_ >= (int)sizeof(cookie_header)) {
			printk("ERROR: http search cookie header is too long");
			return buf;
		}
	}

	if ((prandom_u32() & 0x7) == 0)
		connection = http_search_connections[prandom_u32() %
				ARRAY_SIZE(http_search_connections)];

	len_ = snprintf((char *)buf, *len,
		"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: %s\r\n"
		"Accept: %s\r\n"
		"Accept-Language: %s\r\n"
		"Accept-Encoding: gzip, deflate, br\r\n"
		"%s"
		"%s"
		"Connection: %s\r\n"
		"%s"
		"%s"
		"\r\n",
		path, tpl->host, ua, accept, accept_language, referer_header,
		fetch_headers, connection, cache_header, cookie_header);

	if (len_ < 0) {
		printk("ERROR: snprintf(): %s", "failure");
		return buf;
	} else if (len_ >= *len) {
		printk("ERROR: http search request is too long");
		return buf;
	}

	*len = len_;

	return buf;
}

inline unsigned char *build_http_search_request(unsigned char *buf, int *len)
{
	return build_http_search_request_by_template(buf, len, -1);
}
