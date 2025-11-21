#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define REPEAT 100

static char *outfile = "/home/impervguin/Projects/SlabLeakCollector/bench.txt";
module_param(outfile, charp, 0644);
MODULE_PARM_DESC(outfile, "Output file for benchmark results");

static bool detector_enabled = true;
module_param(detector_enabled, bool, 0644);
MODULE_PARM_DESC(detector_enabled, "Enable slab leak detector");

static struct kmem_cache *test_cache;

static void nullctor(void *addr) {}

static char* get_slab_name(int n_allocs, size_t obj_size, int repeat_num) {
    return kasprintf(GFP_KERNEL, "bench_cahce_%d_%zu_%d", n_allocs, obj_size, repeat_num);
}

static ssize_t write_result(const char *buf, size_t len, const char *filename)
{
    struct file *file;
    loff_t pos = 0;
    ssize_t ret;

    file = filp_open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(file))
        return PTR_ERR(file);

    ret = kernel_write(file, buf, len, &pos);
    filp_close(file, NULL);
    return ret;
}

static s64 run_single_benchmark(int n_allocs, size_t obj_size, int repeat_num)
{
    int i;
    void **ptrs;
    ktime_t start, end;
    s64 delta_ns = 0;

    ptrs = kmalloc_array(n_allocs, sizeof(void *), GFP_KERNEL);
    if (!ptrs)
        return -ENOMEM;

    char *slab_name = get_slab_name(n_allocs, obj_size, repeat_num);

    test_cache = kmem_cache_create(slab_name, obj_size, 0, 0, nullctor);
    if (!test_cache) {
        kfree(ptrs);
        return -ENOMEM;
    }

    start = ktime_get();

    for (i = 0; i < n_allocs; i++) {
        ptrs[i] = kmem_cache_alloc(test_cache, GFP_KERNEL);
    }

    for (i = 0; i < n_allocs; i++)
        if (ptrs[i])
            kmem_cache_free(test_cache, ptrs[i]);

    end = ktime_get();
    delta_ns = ktime_to_ns(ktime_sub(end, start));

    kmem_cache_destroy(test_cache);
    kfree(ptrs);
    return delta_ns;
}

static void run_benchmarks(void)
{
    int allocs[] = {10, 100, 1000, 5000, 10000};
    size_t sizes[] = {32, 128, 512, 1024};
    int i, j, r;
    char buf[256];

    for (i = 0; i < ARRAY_SIZE(allocs); i++) {
        for (j = 0; j < ARRAY_SIZE(sizes); j++) {
            printk(KERN_INFO "Running benchmark with allocs=%d size=%zu\n", allocs[i], sizes[j]);
            for (r = 0; r < REPEAT; r++) {
                s64 t = run_single_benchmark(allocs[i], sizes[j], r);
                snprintf(buf, sizeof(buf),
                     "allocs=%d size=%zu detector=%d time_ns=%lld\n",
                     allocs[i], sizes[j], detector_enabled, t);
                write_result(buf, strlen(buf), outfile);
            }
        }
    }
}

static int __init bench_init(void)
{
    printk(KERN_INFO "Slab benchmark module loaded, writing to %s\n", outfile);
    run_benchmarks();

    return 0;
}

static void __exit bench_exit(void)
{
    printk(KERN_INFO "Slab benchmark module unloaded\n");
}

module_init(bench_init);
module_exit(bench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Benchmark");
MODULE_DESCRIPTION("Slab cache benchmark with optional leak detector");
