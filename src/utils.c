#include <linux/module.h>
#include <linux/kernel.h>

#include "utils.h"

static char *extract_module_name(char *str) {
    char *module_name = NULL;
    char *start = str;
    char *end = str;

    while (*end != '\0') {
        if (*end == '[') {
            start = end + 1;
        } else if (*end == ']') {
            break;
        }
        end++;
    }
    if (*end == '\0' || start == str) {
        return NULL;
    }
    module_name = kmalloc(end - start + 1, GFP_KERNEL);
    if (!module_name) {
        // pr_err("extract_module_name: Failed to allocate module_name\n");
        return NULL;
    }

    memcpy(module_name, start, end - start);
    module_name[end - start] = '\0';

    return module_name;
}

char *get_caller_module_name(void *caller_addr) {
    char *caller_str = NULL;

    caller_str = kasprintf(GFP_KERNEL, "%pS\n", caller_addr);
    if (!caller_str) {
        // pr_err("get_caller_module_name: Failed to allocate caller_str\n");
        return NULL;
    }

    char *module_name = extract_module_name(caller_str);
    if (!module_name) {
        kfree(caller_str);
        // pr_err("get_caller_module_name: Failed to extract module name\n");
        return NULL;
    }

    kfree(caller_str);

    return module_name;
}