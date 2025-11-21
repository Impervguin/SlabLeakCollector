#ifndef NOTIF_H
#define NOTIF_H

#include <linux/notifier.h>

int module_event(struct notifier_block *nb,
    unsigned long action, void *data);

#endif