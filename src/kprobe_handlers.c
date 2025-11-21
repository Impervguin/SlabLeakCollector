#include "kprobe_handlers.h"
#include "storage.h"
#include "utils.h"
#include "log.h"

#ifdef CONFIG_KRETPROBE_ON_RETHOOK
#define GET_RET_ADDR(ri) ((void *) (ri)->node.ret_addr)
#else
#define GET_RET_ADDR(ri) ((void *) (ri)->ret_addr)
#endif

int cb_cache_create_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct create_entrydata *d = (struct create_entrydata *)ri->data;
    d->name = (const char *)regs_get_kernel_argument(regs, 0);
    return 0;
}

int cb_cache_create_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    void *ret_addr = GET_RET_ADDR(ri);
    struct kmem_cache *cache = (void *)regs_return_value(regs);
    char *owner = get_caller_module_name(ret_addr);
    struct create_entrydata *d = (struct create_entrydata *)ri->data;
    

    if (!owner || !cache || strcmp(owner, THIS_MODULE->name) == 0) {
        kfree(owner);
        return 0;
    }

    if (!storage_cache_add(cache, owner, d->name, d->object_size))
        log_err("Failed to store cache_info\n");

    kfree(owner);
    return 0;
}

int cb_cache_destroy_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct destroy_entrydata *d = (struct destroy_entrydata *)ri->data;
    d->cache = (void *)regs_get_kernel_argument(regs, 0);
    return 0;
}

int cb_cache_destroy_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    void *ret_addr = GET_RET_ADDR(ri);
    char *caller = get_caller_module_name(ret_addr);
    if (!caller)
        return 0;
        
    if (!caller || strcmp(caller, THIS_MODULE->name) == 0)
        return 0;
    
    struct destroy_entrydata *d = (struct destroy_entrydata *)ri->data;
    struct cache_info *ci = storage_cache_find(d->cache);

    if (!ci)
        return 0;

    storage_cache_remove(ci);
    
    return 0;
}



int cb_alloc_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct alloc_entrydata *d = (struct alloc_entrydata *)ri->data;
    d->cache = (void *)regs_get_kernel_argument(regs, 0);
    return 0;
}

int cb_alloc_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    void *ret_addr = GET_RET_ADDR(ri);
    char *caller = get_caller_module_name(ret_addr);

    if (!caller || strcmp(caller, THIS_MODULE->name) == 0)
        return 0;

    struct alloc_entrydata *d =  (struct alloc_entrydata *)ri->data;
    struct kmem_cache *cache = d->cache;
    void *obj = (void *)regs_return_value(regs);

    kfree(caller);

    if (!obj)
        return 0;

    struct cache_info *ci = storage_cache_find(cache);
    if (!ci)
        return 0;

    storage_alloc_add(ci, obj);
    return 0;
}


int cb_free_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct free_entrydata *d = (struct free_entrydata *)ri->data;

    d->cache = (void *)regs_get_kernel_argument(regs, 0);
    d->obj   = (void *)regs_get_kernel_argument(regs, 1);
    return 0;
}

int cb_free_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    void *ret_addr = GET_RET_ADDR(ri);
    char *caller = get_caller_module_name(ret_addr);

    if (!caller || strcmp(caller, THIS_MODULE->name) == 0)
        return 0;

    kfree(caller);

    struct free_entrydata *d = (struct free_entrydata *)ri->data;
    struct cache_info *ci = storage_cache_find(d->cache);
    if (!ci)
        return 0;

    struct alloc_info *ai = storage_alloc_find(d->obj);
    if (!ai || ai->cache != ci)
        return 0;

    storage_alloc_remove(ai);
    return 0;
}

struct kretprobe krp_create = {
    .kp.symbol_name = "__kmem_cache_create_args",
    .entry_handler = cb_cache_create_entry,
    .handler = cb_cache_create_ret,
    .maxactive = MAXACTIVE,
    .data_size = sizeof(struct create_entrydata),
};

struct kretprobe krp_alloc = {
    .kp.symbol_name = "kmem_cache_alloc_noprof",
    .entry_handler = cb_alloc_entry,
    .handler = cb_alloc_ret,
    .maxactive = MAXACTIVE,
    .data_size = sizeof(struct alloc_entrydata),
};

struct kretprobe krp_destroy = {
    .kp.symbol_name = "kmem_cache_destroy",
    .entry_handler = cb_cache_destroy_entry,
    .handler = cb_cache_destroy_ret,
    .maxactive = MAXACTIVE,
    .data_size = sizeof(struct destroy_entrydata),
};

struct kretprobe krp_free = {
    .kp.symbol_name = "kmem_cache_free",
    .entry_handler = cb_free_entry,
    .handler = cb_free_ret,
    .maxactive = MAXACTIVE,
    .data_size = sizeof(struct free_entrydata),
};

int register_create_kretprobe(void) {
    return register_kretprobe(&krp_create);
}

int register_alloc_kretprobe(void) {
    return register_kretprobe(&krp_alloc);
}

int register_destroy_kretprobe(void) {
    return register_kretprobe(&krp_destroy);
}

int register_free_kretprobe(void) {
    return register_kretprobe(&krp_free);
}

void unregister_create_kretprobe(void) {
    unregister_kretprobe(&krp_create);
}

void unregister_alloc_kretprobe(void) {
    unregister_kretprobe(&krp_alloc);
}

void unregister_destroy_kretprobe(void) {
    unregister_kretprobe(&krp_destroy);
}

void unregister_free_kretprobe(void) {
    unregister_kretprobe(&krp_free);
}

int disable_destroy_kretprobe(void) {
    return disable_kretprobe(&krp_destroy);
}

int enable_destroy_kretprobe(void) {
    return enable_kretprobe(&krp_destroy);
}

