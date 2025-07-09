#ifndef __GENL_H__
#define __GENL_H__


int genl_report_dns_record(u32 class_id, const char *domain);

int genl_init(void);

int genl_exit(void);


#endif //__GENL_H__

