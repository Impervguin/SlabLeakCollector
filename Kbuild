obj-m := app.o other.o other1.o bench.o
app-y := obj/main.o
app-y += obj/storage.o
app-y += obj/utils.o
app-y += obj/kprobe_handlers.o
app-y += obj/notif.o
other1-y := obj/other1.o
bench-y := obj/bench.o

ccflags-y := -I./inc