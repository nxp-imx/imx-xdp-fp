# Copyright 2025 NXP

# Default values
CC ?= gcc
ARCH ?= arm64
llc ?= llc
clang ?= clang
INSTALLDIR ?= ../deploy_xdp

C_FLAGS := -Wall
C_FLAGS += -I../include/	
L_FLAGS := -lz -lelf -lbpf

TARGETBIN := xdp_fp

INSTALL := install

$(TARGETBIN): xdp_fp_user.c
	$(CC) $(CFLAGS) $(C_FLAGS) $(LDFLAGS) $< $(L_FLAGS) -o $@

install: $(TARGETBIN)
	$(INSTALL) -D -m 755 xdp_fp $(INSTALLDIR)/$(TARGETBIN)
clean:
	rm -rf xdp_fp
