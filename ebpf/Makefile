# Copyright 2025 NXP

# Default values
CC ?= gcc
ARCH ?= arm64
llc ?= llc
clang ?= clang
INSTALLDIR ?= ../deploy_xdp
KERNEL_HEADERS ?= $(SDKTARGETSYSROOT)/usr

CL_FLAGS := -g -O2 -emit-llvm -target bpf -D__aarch64__ -D__KERNEL__ -D__BPF__ -Wall \
	-I$(KERNEL_HEADERS)/include


C_FLAGS := -Wall \
	-I$(KERNEL_HEADERS)/include 
CL_FLAGS += -I../include
C_FLAGS += -I../include/	
L_FLAGS := -lzstd -lz -lelf -lbpf

TARGETPROG := xdp_fp_kern.o

INSTALL := install

all: $(TARGETPROG)
$(TARGETPROG): xdp_fp_kern.bc
	$(llc) $^ -march=bpf -filetype=obj -o $@

xdp_fp_kern.bc: xdp_fp_kern.c
	$(clang) $(CLANG_FLAGS) $(CL_FLAGS) -c $< -o $@

install: all
	$(INSTALL) -D -m 644 $(TARGETPROG) $(INSTALLDIR)/$(TARGETPROG)
clean:
	rm -f *.o
	rm -f *.bc
