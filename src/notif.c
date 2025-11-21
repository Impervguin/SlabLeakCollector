#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleloader.h>
#include "storage.h"
#include "log.h"
#include "notif.h"
#include "kprobe_handlers.h"

static int cleanup_cache_allocs(struct cache_info *ci, struct list_head *alloc_list, const char *mod_name)
{
    struct alloc_info *ai, *tmp_ai;
    int freed = 0;

    list_for_each_entry_safe(ai, tmp_ai, alloc_list, list) {
        if (ai->cache != ci)
            continue;

        log_warn("module %s — freeing leaked alloc %s:%p\n", mod_name, ci->name, ai->obj);
        kmem_cache_free(ci->cache, ai->obj);
        list_del(&ai->list);
        storage_free_alloc_node(ai);
        freed++;
    }

    return freed;
}

static void cleanup_cache_node(struct cache_info *ci, struct list_head *alloc_list, const char *mod_name)
{
    log_warn("module %s — leaked cache detected: %s (%p)\n", mod_name, ci->name, ci->cache);

    int freed_allocs = cleanup_cache_allocs(ci, alloc_list, mod_name);
    log_warn("module %s — freed %d allocs from cache %s\n", mod_name, freed_allocs, ci->name);

    kmem_cache_destroy(ci->cache);
    log_warn("module %s — destroyed cache %s\n", mod_name, ci->name);

    list_del(&ci->list);
    storage_free_cache_node(ci);
}

int module_event(struct notifier_block *nb,
                 unsigned long action,
                 void *data)
{
    struct module *mod = data;

    if (action != MODULE_STATE_GOING)
        return NOTIFY_OK;

    log_info("module %s is unloading — checking slab caches\n", mod->name);

    struct detached_caches detached;
    storage_detach_module_caches(mod->name, &detached);

    if (list_empty(&detached.caches)) {
        log_info("module %s — no leaked caches detected\n", mod->name);
        return NOTIFY_OK;
    }

    struct cache_info *ci, *tmp_ci;
    list_for_each_entry_safe(ci, tmp_ci, &detached.caches, list) {
        cleanup_cache_node(ci, &detached.allocs, mod->name);
    }

    return NOTIFY_OK;
}
