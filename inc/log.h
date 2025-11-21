#ifndef LOG_H
#define LOG_H

#include <linux/printk.h>

#define LOG_PREFIX "+ [%s/%s]: "

#define log_debug(fmt, ...) \
    pr_debug(LOG_PREFIX fmt, KBUILD_MODNAME, __func__, ##__VA_ARGS__)

#define log_info(fmt, ...) \
    pr_info(LOG_PREFIX fmt, KBUILD_MODNAME, __func__, ##__VA_ARGS__)

#define log_warn(fmt, ...) \
    pr_warn(LOG_PREFIX fmt, KBUILD_MODNAME, __func__, ##__VA_ARGS__)

#define log_err(fmt, ...) \
    pr_err(LOG_PREFIX fmt, KBUILD_MODNAME, __func__, ##__VA_ARGS__)

#endif /* LOG_H */