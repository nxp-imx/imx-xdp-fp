# Copyright 2025 NXP

SUBDIRS = app ebpf

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

install:
	$(MAKE) -C app install
	$(MAKE) -C ebpf install

clean:
	$(MAKE) -C app clean
	$(MAKE) -C ebpf clean


.PHONY: all app ebpf install clean
