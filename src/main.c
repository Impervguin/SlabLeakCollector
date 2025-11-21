#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/init.h>

#include "storage.h"
#include "kprobe_handlers.h"
#include "log.h"
#include "notif.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("impervguin");
MODULE_DESCRIPTION("A simple module to find the caller module");

static struct notifier_block module_nb = {
    .notifier_call = module_event,
};

static int __init init(void) {
    int ret = storage_init();
    if (ret < 0) {
        log_err("init_cache_storage failed: %d\n", ret);
        return ret;
    }
    ret = register_create_kretprobe();
    if (ret < 0)
        log_err("register_create_kretprobe failed: %d\n", ret);
    log_info("Registered kretprobe for kmem_cache_create\n");
    ret = register_alloc_kretprobe();
    if (ret < 0)
        log_err("register_alloc_kretprobe failed: %d\n", ret);
    log_info("Registered kretprobe for kmem_cache_alloc\n");
    ret = register_destroy_kretprobe();
    if (ret < 0)
        log_err("register_destroy_kretprobe failed: %d\n", ret);
    log_info("Registered kretprobe for kmem_cache_destroy\n");
    ret = register_free_kretprobe();
    if (ret < 0)
        log_err("register_free_kretprobe failed: %d\n", ret);
    log_info("Registered kretprobe for kmem_cache_free\n");
    register_module_notifier(&module_nb);
    return 0;
}

static void __exit exit(void) {
    unregister_create_kretprobe();
    unregister_alloc_kretprobe();
    unregister_destroy_kretprobe();
    unregister_free_kretprobe();
    unregister_module_notifier(&module_nb);

    synchronize_rcu();
    storage_destroy();
}
module_init(init);
module_exit(exit);

