#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/init.h>

#include "storage.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("impervguin");
MODULE_DESCRIPTION("A simple module to find the caller module");

static int module_event(struct notifier_block *nb,
    unsigned long action, void *data)
{
struct module *mod = data;

printk(KERN_INFO "Module %s notified of %lu\n", mod->name, action);
list_cache_info();

return NOTIFY_OK;
}

static struct notifier_block module_nb = {
.notifier_call = module_event,
};

static struct kretprobe krp = {
    .kp.symbol_name = "__kmem_cache_create_args",
    .handler = create_rethandler,
    .maxactive = 128,
};

static struct kretprobe krp_alloc = {
    .kp.symbol_name = "kmem_cache_alloc_noprof",
    .entry_handler = alloc_entryhandler,
    .handler = alloc_rethandler,
    .maxactive = 128,
    .data_size = sizeof(struct alloc_entrydata),
};

static struct kretprobe krp_destroy = {
    .kp.symbol_name = "kmem_cache_destroy",
    .entry_handler = destroy_entryhandler,
    .handler = destroy_rethandler,
    .maxactive = 128,
    .data_size = sizeof(struct destroy_entrydata),
};

static struct kretprobe krp_free = {
    .kp.symbol_name = "kmem_cache_free",
    .entry_handler = free_entryhandler,
    .handler = free_rethandler,
    .maxactive = 128,
    .data_size = sizeof(struct free_entrydata),
};

static int __init init(void)
{
    int ret = init_cache_storage();
    if (ret < 0) {
        pr_err("init_cache_storage failed: %d\n", ret);
        return ret;
    }
    ret = register_kretprobe(&krp);
    if (ret < 0) {
        pr_err("register_kretprobe failed: %d\n", ret);
        return ret;
    }
    pr_info("Registered kretprobe for %s\n", krp.kp.symbol_name);
    ret = register_kretprobe(&krp_alloc);
    if (ret < 0) {
        pr_err("register_kretprobe failed: %d\n", ret);
        return ret;
    }
    pr_info("Registered kretprobe for %s\n", krp_alloc.kp.symbol_name);
    ret = register_kretprobe(&krp_destroy);
    if (ret < 0) {
        pr_err("register_kretprobe failed: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "Registered kretprobe for %s\n", krp_destroy.kp.symbol_name);

    ret = register_kretprobe(&krp_free);
    if (ret < 0) {
        pr_err("register_kretprobe failed: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "Registered kretprobe for %s\n", krp_free.kp.symbol_name);
    register_module_notifier(&module_nb);
    return 0;
}

static void __exit exit(void)
{
    unregister_kretprobe(&krp);
    unregister_kretprobe(&krp_alloc);
    unregister_kretprobe(&krp_destroy);
    unregister_kretprobe(&krp_free);
    unregister_module_notifier(&module_nb);

    synchronize_rcu();
    destroy_cache_storage();
}
module_init(init);
module_exit(exit);

