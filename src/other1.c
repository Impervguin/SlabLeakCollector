#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("impervguin");
MODULE_DESCRIPTION("A simple module to find the caller module");

static struct kmem_cache *test;
void *obj;

static int __init init(void)
{
    printk(KERN_INFO "Calling kmem_cache_create\n");
    test = kmem_cache_create("super_secret_cache_m_test_ag", 1024, 0, 0, NULL);
    obj = kmem_cache_alloc(test, GFP_KERNEL);
    printk(KERN_INFO "kmem_cache_create returned %p\n", test);
    return 0;
}

static void __exit exit(void)
{
    kmem_cache_free(test, obj);
    kmem_cache_destroy(test);
    printk(KERN_INFO "Goodbye, world!\n");
}

module_init(init);
module_exit(exit);