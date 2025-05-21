#ifndef __DNSLISTEN_COMMON_H__
#define __DNSLISTEN_COMMON_H__

#define __log(fmt, ...) printk("nf_dnslisten  func: %s line: %d file: %s "fmt"\n", __FUNCTION__, __LINE__, __FILE__, ##__VA_ARGS__)

#endif //__DNSLISTEN_COMMON_H__