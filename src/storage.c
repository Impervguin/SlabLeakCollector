#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>

#include "storage.h"
#include "utils.h"

static LIST_HEAD(cache_list);
static LIST_HEAD(alloc_list);
static DEFINE_SPINLOCK(cache_storage_lock);

static struct kmem_cache *cache_info_cache;
static struct kmem_cache *alloc_info_cache;

void _list_cache_info(void);
void _list_alloc_info_by_cache(struct cache_info *cache);

int init_cache_storage(void) {
    INIT_LIST_HEAD(&cache_list);
    INIT_LIST_HEAD(&alloc_list);

    cache_info_cache = kmem_cache_create("cache_info_cache", sizeof(struct cache_info), 0, 0, NULL);

    if (!cache_info_cache) {
        spin_unlock(&cache_storage_lock);
        pr_err("Failed to create cache_info_cache\n");
        return -ENOMEM;
    }

    alloc_info_cache = kmem_cache_create("alloc_info_cache", sizeof(struct alloc_info), 0, 0, NULL);

    if (!alloc_info_cache) {
        spin_unlock(&cache_storage_lock);
        kmem_cache_destroy(cache_info_cache);
        pr_err("Failed to create alloc_info_cache\n");
        return -ENOMEM;
    }

    return 0;
}

void destroy_cache_storage(void) {
    struct alloc_info *ea;
    struct alloc_info *na;

    struct cache_info *ec;
    struct cache_info *nc;
    pr_info("destroy_cache_storage: start\n");
    list_for_each_entry_safe(ea, na, &alloc_list, list) {
        list_del(&ea->list);
        kmem_cache_free(alloc_info_cache, ea);
    }
    pr_info("destroy_cache_storage: alloc_list cleared\n");
    list_for_each_entry_safe(ec, nc, &cache_list, list) {
        kfree(ec->owner);
        list_del(&ec->list);
        kmem_cache_free(cache_info_cache, ec);
    }
    pr_info("destroy_cache_storage: cache_list cleared\n");
    kmem_cache_destroy(alloc_info_cache);
    pr_info("destroy_cache_storage: alloc_info_cache destroyed\n");
    kmem_cache_destroy(cache_info_cache);
    pr_info("destroy_cache_storage: cache_info_cache destroyed\n");
}

static struct cache_info *_find_cache_info(struct kmem_cache *cache) {
    struct cache_info *cache_info;
    list_for_each_entry(cache_info, &cache_list, list) {
        if (cache_info->cache == cache) {
            return cache_info;
        }
    }
    return NULL;
}
    
int create_rethandler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    spin_lock(&cache_storage_lock);
    void *ret_addr;
    #ifdef CONFIG_KRETPROBE_ON_RETHOOK
        ret_addr = (void *) ri->node.ret_addr;
    #else
        ret_addr = (void *) ri->ret_addr;
    #endif

    struct cache_info tmp = {
        .owner = get_caller_module_name(ret_addr),
        .cache = (struct kmem_cache *) regs_return_value(regs),
        .list = LIST_HEAD_INIT(tmp.list),
    };
    
    if (!tmp.owner) {
        spin_unlock(&cache_storage_lock);
        pr_err("create_rethandler: Failed to get caller module name, may be not module.\n");
        return 0;
    }

    if (!tmp.cache) {
        spin_unlock(&cache_storage_lock);
        pr_err("create_rethandler: Failed to get cache\n");
        return 0;
    }

    pr_info("create_rethandler: cache: %p\n", tmp.cache);
    pr_info("create_rethandler: owner: %s\n", tmp.owner);

    struct cache_info *cache = kmem_cache_alloc(cache_info_cache, GFP_KERNEL);
    if (!cache) {
        spin_unlock(&cache_storage_lock);
        pr_err("create_rethandler: Failed to allocate cache_info\n");
        return -ENOMEM;
    }
    memcpy(cache, &tmp, sizeof(struct cache_info));

    list_add(&cache->list, &cache_list);
    spin_unlock(&cache_storage_lock);
    return 0;
}

int destroy_entryhandler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct destroy_entrydata *data = (struct destroy_entrydata *) ri->data;

    data->cache = (struct kmem_cache *) regs_get_kernel_argument(regs, 0);
    if (!data->cache) {
        pr_err("destroy_entryhandler: Failed to get cache\n");
        return 0;
    }
    pr_info("destroy_entryhandler: Cache: %p\n", data->cache);
    return 0;
}

int destroy_rethandler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    void *ret_addr;
    #ifdef CONFIG_KRETPROBE_ON_RETHOOK
        ret_addr = (void *) ri->node.ret_addr;
    #else
        ret_addr = (void *) ri->ret_addr;
    #endif

    struct destroy_entrydata *data = (struct destroy_entrydata *) ri->data;
    struct kmem_cache *cache = data->cache;
    pr_info("destroy_rethandler: Cache: %p\n", cache);

    spin_lock(&cache_storage_lock);
    struct cache_info *info = _find_cache_info(cache);
    if (!info) {
        spin_unlock(&cache_storage_lock);
        pr_err("destroy_rethandler: Failed to find cache info\n");
        return 0;
    }

    pr_warn("destroy_rethandler: cache: %p\n", cache);
    pr_warn("destroy_rethandler: owner: %s\n", info->owner);
    pr_warn("destroy_rethandler: not freed cache objects:\n");
    _list_alloc_info_by_cache(info);

    // delete alloc info of this cache
    struct alloc_info *ea;
    struct alloc_info *na;
    list_for_each_entry_safe(ea, na, &alloc_list, list) {
        if (ea->cache == info) {
            list_del(&ea->list);
            kmem_cache_free(alloc_info_cache, ea);
        }
    }

    // delete cache info
    list_del(&info->list);
    kmem_cache_free(cache_info_cache, info);
    spin_unlock(&cache_storage_lock);
    return 0;
}

int alloc_entryhandler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct alloc_entrydata *data = (struct alloc_entrydata *) ri->data;

    data->cache = (struct kmem_cache *) regs_get_kernel_argument(regs, 0);
    if (!data->cache) {
        pr_err("alloc_entryhandler: Failed to get cache\n");
        return 0;
    }
    return 0;
}

int alloc_rethandler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    void *ret_addr;
    #ifdef CONFIG_KRETPROBE_ON_RETHOOK
        ret_addr = (void *) ri->node.ret_addr;
    #else
        ret_addr = (void *) ri->ret_addr;
    #endif

    const char *caller = get_caller_module_name(ret_addr);
    if (!caller) { // may be not module
        return 0;
    }
    struct alloc_entrydata *data = (struct alloc_entrydata *) ri->data;
    struct kmem_cache *cache = data->cache;

    struct alloc_info *alloc = kmem_cache_alloc(alloc_info_cache, GFP_KERNEL);
    if (!alloc) {
        spin_unlock(&cache_storage_lock);
        kfree(caller);
        pr_err("alloc_rethandler: Failed to allocate alloc_info\n");
        return -ENOMEM;
    }
    alloc->obj = (void *) regs_return_value(regs);
    if (!alloc->obj) {
        spin_unlock(&cache_storage_lock);
        kfree(caller);
        kmem_cache_free(alloc_info_cache, alloc);
        pr_err("alloc_rethandler: Failed to get obj\n");
        return -ENOMEM;
    }

    spin_lock(&cache_storage_lock);
    struct cache_info *info = _find_cache_info(cache);
    if (!info) {
        spin_unlock(&cache_storage_lock);
        kfree(caller);
        kmem_cache_free(alloc_info_cache, alloc);
        return 0;
    }

    pr_info("alloc_rethandler: cache: %p\n", cache);
    pr_info("alloc_rethandler: owner: %s\n", info->owner);

    alloc->cache = info;
    INIT_LIST_HEAD(&alloc->list);
    list_add(&alloc->list, &alloc_list);
    spin_unlock(&cache_storage_lock);
    return 0;
}

int free_entryhandler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct free_entrydata *data = (struct free_entrydata *) ri->data;

    data->cache = (struct kmem_cache *) regs_get_kernel_argument(regs, 0);
    if (!data->cache) {
        pr_err("free_entryhandler: Failed to get cache\n");
        return 0;
    }

    data->obj = (void *) regs_get_kernel_argument(regs, 1);
    if (!data->obj) {
        pr_err("free_entryhandler: Failed to get obj\n");
        return 0;
    }
    return 0;
}

struct alloc_info *_find_alloc_info(void *obj) {
    struct alloc_info *alloc_info;
    list_for_each_entry(alloc_info, &alloc_list, list) {
        if (alloc_info->obj == obj) {
            return alloc_info;
        }
    }
    return NULL;
}

int free_rethandler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    void *ret_addr;
    #ifdef CONFIG_KRETPROBE_ON_RETHOOK
        ret_addr = (void *) ri->node.ret_addr;
    #else
        ret_addr = (void *) ri->ret_addr;
    #endif

    struct free_entrydata *data = (struct free_entrydata *) ri->data;
    struct kmem_cache *cache = data->cache;
    void *obj = data->obj;

    spin_lock(&cache_storage_lock);
    struct cache_info *info = _find_cache_info(cache);
    if (!info) {
        spin_unlock(&cache_storage_lock);
        return 0;
    }

    struct alloc_info *ainfo = _find_alloc_info(obj);
    if (!ainfo) {
        spin_unlock(&cache_storage_lock);
        return 0;
    }

    if (ainfo->cache != info) {
        spin_unlock(&cache_storage_lock);
        return 0;
    }

    list_del(&ainfo->list);
    spin_unlock(&cache_storage_lock);
    kmem_cache_free(alloc_info_cache, ainfo);
    return 0;
}
    

void _list_cache_info(void) {
    struct cache_info *cache;
    list_for_each_entry(cache, &cache_list, list) {
        pr_info("cache: %p\n", cache->cache);
        pr_info("owner: %s\n", cache->owner);
    }
}

void list_cache_info(void) {
    spin_lock(&cache_storage_lock);
    _list_cache_info();
    spin_unlock(&cache_storage_lock);
}

void  _list_alloc_info_by_cache(struct cache_info *cache) {
    struct alloc_info *alloc;
    list_for_each_entry(alloc, &alloc_list, list) {
        if (alloc->cache == cache) {
            pr_info("alloc: %p\n", alloc->obj);
        }
    }
}

void list_alloc_info_by_cache(struct cache_info *cache) {
    spin_lock(&cache_storage_lock);
    _list_alloc_info_by_cache(cache);
    spin_unlock(&cache_storage_lock);
}