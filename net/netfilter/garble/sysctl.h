int garble_sysctl_init(void);

void garble_sysctl_exit(void);

inline const char *garble_get_random_domain(void);

inline bool garble_check_if_enabled(void);

inline bool garble_check_if_http_enabled(void);

inline bool garble_check_if_tls_enabled(void);

inline bool garble_check_if_double_enabled(void);

inline bool garble_check_if_udp_enabled(void);
