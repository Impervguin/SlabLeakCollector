#include "storage.h"
#include <linux/slab.h>
#include <linux/printk.h>

static LIST_HEAD(cache_list);
static LIST_HEAD(alloc_list);
static DEFINE_SPINLOCK(storage_lock);

static struct kmem_cache *cache_info_cache;
static struct kmem_cache *alloc_info_cache;


int storage_init(void)
{
    cache_info_cache = kmem_cache_create("cache_info_cache",
                                         sizeof(struct cache_info),
                                         0, 0, NULL);
    if (!cache_info_cache) {
        pr_err("storage: failed to create cache_info_cache\n");
        return -ENOMEM;
    }

    alloc_info_cache = kmem_cache_create("alloc_info_cache",
                                         sizeof(struct alloc_info),
                                         0, 0, NULL);
    if (!alloc_info_cache) {
        kmem_cache_destroy(cache_info_cache);
        pr_err("storage: failed to create alloc_info_cache\n");
        return -ENOMEM;
    }
    return 0;
}

void storage_destroy(void)
{
    struct alloc_info *ai, *an;
    struct cache_info *ci, *cn;

    spin_lock(&storage_lock);

    list_for_each_entry_safe(ai, an, &alloc_list, list) {
        list_del(&ai->list);
        kmem_cache_free(alloc_info_cache, ai);
    }

    list_for_each_entry_safe(ci, cn, &cache_list, list) {
        kfree(ci->owner);
        kfree(ci->name);
        list_del(&ci->list);
        kmem_cache_free(cache_info_cache, ci);
    }

    spin_unlock(&storage_lock);

    kmem_cache_destroy(alloc_info_cache);
    kmem_cache_destroy(cache_info_cache);
}


/* ---------------- Cache operations ---------------- */

struct cache_info *storage_cache_add(struct kmem_cache *cache, const char *owner, const char *name, unsigned long object_size)
{
    struct cache_info *ci;

    ci = kmem_cache_alloc(cache_info_cache, GFP_KERNEL);
    if (!ci)
        return NULL;

    ci->cache = cache;
    ci->owner = kstrdup(owner, GFP_KERNEL);
    ci->name = kstrdup(name, GFP_KERNEL);
    ci->object_size = object_size;
    INIT_LIST_HEAD(&ci->list);

    spin_lock(&storage_lock);
    list_add(&ci->list, &cache_list);
    spin_unlock(&storage_lock);
    return ci;
}

struct cache_info *storage_cache_find(struct kmem_cache *cache)
{
    struct cache_info *ci;

    spin_lock(&storage_lock);
    list_for_each_entry(ci, &cache_list, list) {
        if (ci->cache == cache) {
            spin_unlock(&storage_lock);
            return ci;
        }
    }
    spin_unlock(&storage_lock);
    return NULL;
}

void storage_cache_remove(struct cache_info *ci)
{
    struct alloc_info *ai, *an;

    spin_lock(&storage_lock);

    list_for_each_entry_safe(ai, an, &alloc_list, list) {
        if (ai->cache == ci) {
            list_del(&ai->list);
            kmem_cache_free(alloc_info_cache, ai);
        }
    }

    list_del(&ci->list);
    spin_unlock(&storage_lock);

    kfree(ci->owner);
    kfree(ci->name);
    kmem_cache_free(cache_info_cache, ci);
}

void storage_cache_remove_nolock(struct cache_info *ci)
{
    struct alloc_info *ai, *an;
    
    list_for_each_entry_safe(ai, an, &alloc_list, list) {
        if (ai->cache == ci) {
            list_del(&ai->list);
            kmem_cache_free(alloc_info_cache, ai);
        }
    }
    list_del(&ci->list);
    kfree(ci->owner);
    kfree(ci->name);
    kmem_cache_free(cache_info_cache, ci);
}


/* ---------------- Alloc operations ---------------- */

struct alloc_info *storage_alloc_add(struct cache_info *cache, void *obj)
{
    struct alloc_info *ai = kmem_cache_alloc(alloc_info_cache, GFP_KERNEL);
    if (!ai)
        return NULL;

    ai->cache = cache;
    ai->obj = obj;
    INIT_LIST_HEAD(&ai->list);

    spin_lock(&storage_lock);
    list_add(&ai->list, &alloc_list);
    spin_unlock(&storage_lock);

    return ai;
}

struct alloc_info *storage_alloc_find(void *obj)
{
    struct alloc_info *ai;

    spin_lock(&storage_lock);
    list_for_each_entry(ai, &alloc_list, list) {
        if (ai->obj == obj) {
            spin_unlock(&storage_lock);
            return ai;
        }
    }
    spin_unlock(&storage_lock);
    return NULL;
}

void storage_alloc_remove(struct alloc_info *ai)
{
    spin_lock(&storage_lock);
    list_del(&ai->list);
    spin_unlock(&storage_lock);

    kmem_cache_free(alloc_info_cache, ai);
}

void storage_alloc_remove_nolock(struct alloc_info *ai)
{
    list_del(&ai->list);
    kmem_cache_free(alloc_info_cache, ai);
}


/* ---------------- Debug ---------------- */

void storage_list_caches(void)
{
    struct cache_info *ci;

    spin_lock(&storage_lock);
    list_for_each_entry(ci, &cache_list, list) {
        pr_info("cache=%p owner=%s\n", ci->cache, ci->owner);
    }
    spin_unlock(&storage_lock);
}

void storage_list_allocs(struct cache_info *cache)
{
    struct alloc_info *ai;

    spin_lock(&storage_lock);
    list_for_each_entry(ai, &alloc_list, list) {
        if (ai->cache == cache)
            pr_info("alloc=%p\n", ai->obj);
    }
    spin_unlock(&storage_lock);
}


/* ---------------- traversal ---------------- */

void storage_for_each_alloc_per_cache(struct cache_info *ci,
    alloc_iter_fn fn,
    void *user) {
    struct alloc_info *ai;

    if (!ci || !fn)
        return;

    spin_lock(&storage_lock);

    list_for_each_entry(ai, &alloc_list, list) {
        if (ai->cache == ci)
            fn(ai, user);
    }

    spin_unlock(&storage_lock);
}

void storage_for_each_alloc_per_cache_nolock(struct cache_info *ci,
                                             alloc_iter_fn fn,
                                             void *user) {
    struct alloc_info *ai;

    if (!ci || !fn)
        return;

    list_for_each_entry(ai, &alloc_list, list) {
        if (ai->cache == ci)
            fn(ai, user);
    }
}

void storage_for_each_cache(cache_iter_fn fn, void *user)
{
    struct cache_info *ci;

    spin_lock(&storage_lock);

    list_for_each_entry(ci, &cache_list, list) {
        fn(ci, user);
    }

    spin_unlock(&storage_lock);
}

void storage_for_each_alloc(alloc_iter_fn fn, void *user)
{
    struct alloc_info *ai;

    spin_lock(&storage_lock);

    list_for_each_entry(ai, &alloc_list, list) {
        fn(ai, user);
    }

    spin_unlock(&storage_lock);
}

void storage_for_each_alloc_per_cache_safe(struct cache_info *ci,
    alloc_iter_fn fn,
    void *user) {
    struct alloc_info *ai, *tmp;

    if (!ci || !fn)
        return;

    spin_lock(&storage_lock);

    list_for_each_entry_safe(ai, tmp, &alloc_list, list) {
        if (ai->cache == ci)
            fn(ai, user); 
    }

    spin_unlock(&storage_lock);
}

void storage_for_each_alloc_per_cache_nolock_safe(struct cache_info *ci,
                                                  alloc_iter_fn fn,
                                                  void *user) {
    struct alloc_info *ai, *tmp;

    if (!ci || !fn)
        return;

    list_for_each_entry_safe(ai, tmp, &alloc_list, list) {
        if (ai->cache == ci)
            fn(ai, user); 
    }
}

void storage_for_each_cache_safe(cache_iter_fn fn, void *user)
{
    struct cache_info *ci, *tmp;

    spin_lock(&storage_lock);

    list_for_each_entry_safe(ci, tmp, &cache_list, list) {
        fn(ci, user);
    }

    spin_unlock(&storage_lock);
}

void storage_for_each_alloc_safe(alloc_iter_fn fn, void *user)
{
    struct alloc_info *ai, *tmp;

    spin_lock(&storage_lock);

    list_for_each_entry_safe(ai, tmp, &alloc_list, list) {
        fn(ai, user);
    }

    spin_unlock(&storage_lock);
}


int storage_detach_module_caches(const char *owner, struct detached_caches *out)
{
    struct cache_info *ci, *tmp_ci;
    struct alloc_info *ai, *tmp_ai;

    if (!owner || !out)
        return -EINVAL;

    INIT_LIST_HEAD(&out->caches);
    INIT_LIST_HEAD(&out->allocs);

    spin_lock(&storage_lock);
    list_for_each_entry_safe(ci, tmp_ci, &cache_list, list) {
        if (strcmp(ci->owner, owner) == 0) {
            list_del(&ci->list);
            list_add_tail(&ci->list, &out->caches);
        }
    }

    list_for_each_entry_safe(ai, tmp_ai, &alloc_list, list) {
        struct cache_info *found = NULL;
        list_for_each_entry(ci, &out->caches, list) {
            if (ai->cache == ci) { found = ci; break; }
        }
        if (found) {
            list_del(&ai->list);
            list_add_tail(&ai->list, &out->allocs);
        }
    }

    spin_unlock(&storage_lock);
    return 0;
}

void storage_free_cache_node(struct cache_info *ci)
{
    if (!ci) return;
    kfree(ci->owner);
    kfree(ci->name);
    kmem_cache_free(cache_info_cache, ci);
}

void storage_free_alloc_node(struct alloc_info *ai)
{
    if (!ai) return;
    kmem_cache_free(alloc_info_cache, ai);
}
