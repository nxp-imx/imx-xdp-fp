# Copyright 2025 NXP

# Default values
CC ?= gcc
ARCH ?= arm64
llc ?= llc
clang ?= clang
PREFIX ?= /usr
KERNEL_HEADERS ?= $(SDKTARGETSYSROOT)/usr

C_FLAGS := -Wall \
	-I$(KERNEL_HEADERS)/include 
C_FLAGS += -I../include/	
L_FLAGS := -lz -lelf -lbpf

BINDIR := $(PREFIX)/bin
TARGETBIN := xdp_fp

INSTALL := install

$(TARGETBIN): xdp_fp_user.c
	$(CC) $(CFLAGS) $(C_FLAGS) $(LDFLAGS) $< $(L_FLAGS) -o $@

install: $(TARGETBIN)
	$(INSTALL) -D -m 755 xdp_fp $(DESTDIR)$(BINDIR)/$(TARGETBIN)
clean:
	rm -rf xdp_fp
