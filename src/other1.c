#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("impervguin");
MODULE_DESCRIPTION("A simple module to find the caller module");

static struct kmem_cache *test;
static struct kmem_cache *test2;
void *objarr[64];

static void secret_constructor(void *addr)
{
    memset(addr, 0, 1024);
}

static int __init init(void)
{
    printk(KERN_INFO "Calling kmem_cache_create\n");
    test = kmem_cache_create("super_secret_cache", 1024, 0, 0, secret_constructor);
    for (int i = 0; i < 64; i++) {
        objarr[i] = kmem_cache_alloc(test, GFP_KERNEL);
    }
    test2 = kmem_cache_create("super_secret_cache2", 1024, 0, 0, secret_constructor);
    printk(KERN_INFO "kmem_cache_create returned %p\n", test);
    return 0;
}

static void __exit exit(void) {
    // for (int i = 0; i < 64; i++) {
    //     kmem_cache_free(test, objarr[i]);
    // }
    // kmem_cache_destroy(test);
    // kmem_cache_destroy(test2);
    printk(KERN_INFO "Goodbye, world! My cache is %p\n", test);
}

module_init(init);
module_exit(exit);