#include <linux/version.h>


int garble_sysctl_init(void);
void garble_sysctl_exit(void);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)

inline const char *garble_get_random_domain(void);
inline bool garble_check_if_enabled(void);
inline bool garble_check_if_http_enabled(void);
inline bool garble_check_if_tls_enabled(void);
inline bool garble_check_if_double_enabled(void);
inline bool garble_check_if_udp_enabled(void);

#else
extern const char *garble_get_random_domain(void);
extern bool garble_check_if_enabled(void);
extern bool garble_check_if_http_enabled(void);
extern bool garble_check_if_tls_enabled(void);
extern bool garble_check_if_double_enabled(void);
extern bool garble_check_if_udp_enabled(void);

#endif