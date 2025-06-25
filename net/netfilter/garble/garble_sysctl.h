int garble_sysctl_init(void);

void garble_sysctl_exit(void);

const char *garble_get_random_domain(void);

bool garble_check_if_enabled(void);

#undef __log
#define __log(fmt, ...) printk("garble func: %s line: %d file: %s "fmt"\n", __FUNCTION__, __LINE__, __FILE__, ##__VA_ARGS__)
