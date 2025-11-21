#ifndef STORAGE_H
#define STORAGE_H

#include <linux/kmemleak.h>
#include <linux/list.h>
#include <linux/spinlock.h>

struct cache_info {
    char *name;
    unsigned long object_size;
    struct kmem_cache *cache;
    char *owner;
    struct list_head list;
};

struct alloc_info {
    struct cache_info *cache;
    void *obj;
    struct list_head list;
};

/* Initialize/destroy singleton storage */
int storage_init(void);
void storage_destroy(void);

/* Cache info management */
struct cache_info *storage_cache_add(struct kmem_cache *cache, const char *owner, const char *name, unsigned long object_size);
struct cache_info *storage_cache_find(struct kmem_cache *cache);
void storage_cache_remove(struct cache_info *info);
void storage_cache_remove_nolock(struct cache_info *info); // for use in safe traversal

/* Alloc info management */
struct alloc_info *storage_alloc_add(struct cache_info *cache, void *obj);
struct alloc_info *storage_alloc_find(void *obj);
void storage_alloc_remove(struct alloc_info *info);
void storage_alloc_remove_nolock(struct alloc_info *info); // for use in safe traversal

/* Debug */
void storage_list_caches(void);
void storage_list_allocs(struct cache_info *cache);


/* list traversal */
typedef void (*cache_iter_fn)(struct cache_info *ci, void *user);
typedef void (*alloc_iter_fn)(struct alloc_info *ai, void *user);

void storage_for_each_alloc_per_cache(struct cache_info *ci,
                                      alloc_iter_fn fn,
                                      void *user);
void storage_for_each_alloc_per_cache_nolock(struct cache_info *ci,
                                             alloc_iter_fn fn,
                                             void *user); // for use in other traversal
void storage_for_each_cache(cache_iter_fn fn, void *user);
void storage_for_each_alloc(alloc_iter_fn fn, void *user);
                                      
void storage_for_each_alloc_per_cache_safe(struct cache_info *ci,
                                           alloc_iter_fn fn,
                                           void *user);
void storage_for_each_cache_safe(cache_iter_fn fn, void *user);
void storage_for_each_alloc_safe(alloc_iter_fn fn, void *user);
void storage_for_each_alloc_per_cache_nolock_safe(struct cache_info *ci,
                                                  alloc_iter_fn fn,
                                                  void *user); // for use in other traversals

/* Detaches*/
struct detached_caches {
    struct list_head caches;   
    struct list_head allocs;   
};

int storage_detach_module_caches(const char *owner, struct detached_caches *out);

void storage_free_cache_node(struct cache_info *ci);
void storage_free_alloc_node(struct alloc_info *ai);


#endif
