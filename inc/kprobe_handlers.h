#ifndef KPROBE_HANDLERS_H
#define KPROBE_HANDLERS_H

#include <linux/kprobes.h>

#define MAXACTIVE 64

struct create_entrydata {
    const char *name;
    unsigned long object_size;
};

struct destroy_entrydata {
    struct kmem_cache *cache;   
};

struct alloc_entrydata {
    struct kmem_cache *cache;
};

struct free_entrydata {
    struct kmem_cache *cache;
    void *obj;
};

int cb_cache_create_entry(struct kretprobe_instance *ri, struct pt_regs *regs);
int cb_cache_create_ret(struct kretprobe_instance *ri, struct pt_regs *regs);

int cb_cache_destroy_entry(struct kretprobe_instance *ri, struct pt_regs *regs);
int cb_cache_destroy_ret(struct kretprobe_instance *ri, struct pt_regs *regs);

int cb_alloc_entry(struct kretprobe_instance *ri, struct pt_regs *regs);
int cb_alloc_ret(struct kretprobe_instance *ri, struct pt_regs *regs);

int cb_free_entry(struct kretprobe_instance *ri, struct pt_regs *regs);
int cb_free_ret(struct kretprobe_instance *ri, struct pt_regs *regs);

int register_create_kretprobe(void);
int register_alloc_kretprobe(void);
int register_destroy_kretprobe(void);
int register_free_kretprobe(void);

void unregister_create_kretprobe(void);
void unregister_alloc_kretprobe(void);
void unregister_destroy_kretprobe(void);
void unregister_free_kretprobe(void);

int disable_destroy_kretprobe(void);
int enable_destroy_kretprobe(void);

#endif
