#ifndef __GARBLE_EMAIL_H__
#define __GARBLE_EMAIL_H__

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)

inline const char *get_email_name(void);
inline const char *get_email(void);

#else

extern const char *get_email_name(void);
extern const char *get_email(void);

#endif

#endif
