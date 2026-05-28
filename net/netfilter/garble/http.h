#ifndef __GARBLE_HTTP_H__
#define __GARBLE_HTTP_H__

const char *garble_http_random_user_agent(void);

unsigned char *build_http_request(unsigned char *buf, int *len,
				  const char *host);
unsigned char *build_http_download_request(unsigned char *buf, int *len,
					   const char *host);
unsigned char *build_http_search_request(unsigned char *buf, int *len);
unsigned char *build_http_search_request_by_template(unsigned char *buf,
						     int *len,
						     int template_id);

#endif
