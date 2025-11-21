#ifndef STORAGE_H
#define STORAGE_H

#include <linux/kprobes.h>

struct cache_info {
    const char *owner;
    struct kmem_cache *cache;

    struct list_head list;
};

struct alloc_info {
    void *obj;
    struct cache_info *cache;

    struct list_head list;
};


int init_cache_storage(void);
void destroy_cache_storage(void);

int create_rethandler(struct kretprobe_instance *ri, struct pt_regs *regs);

int destroy_rethandler(struct kretprobe_instance *ri, struct pt_regs *regs);
struct destroy_entrydata {
    struct kmem_cache *cache;   
};
int destroy_entryhandler(struct kretprobe_instance *ri, struct pt_regs *regs);

int alloc_rethandler(struct kretprobe_instance *ri, struct pt_regs *regs);
struct alloc_entrydata {
    struct kmem_cache *cache;
};
int alloc_entryhandler(struct kretprobe_instance *ri, struct pt_regs *regs);

int free_rethandler(struct kretprobe_instance *ri, struct pt_regs *regs);
struct free_entrydata {
    struct kmem_cache *cache;
    void *obj;
};
int free_entryhandler(struct kretprobe_instance *ri, struct pt_regs *regs);

void list_cache_info(void);
void list_alloc_info_by_cache(struct cache_info *cache);

#endif