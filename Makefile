

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
CC   := clang
LINK := ld.lld

SRCDIR := src
OBJDIR := obj

all: $(OBJDIR)
	cp -rT $(SRCDIR)/ $(OBJDIR)/
	$(MAKE) -C $(KDIR) M=$(PWD) CC=$(CC) LD=$(LINK) modules
	rm -rf $(OBJDIR)/*.c

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf $(OBJDIR)
