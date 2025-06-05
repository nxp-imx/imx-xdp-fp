# Copyright 2025 NXP

# Default values
CC ?= gcc
ARCH ?= arm64
llc ?= llc
clang ?= clang --sysroot=$(SDKTARGETSYSROOT)
INSTALLDIR ?= ../deploy_xdp

CL_FLAGS := -g -O3 -emit-llvm -target bpf -D__aarch64__ -D__KERNEL__ -D__BPF__ -Wall
CL_FLAGS += -I../include

C_FLAGS := -Wall
C_FLAGS += -I../include/
L_FLAGS := -lzstd -lz -lelf -lbpf

TARGETPROG := xdp_fp_kern.o

INSTALL := install

# Intermediate files
BC_FILES := xdp_fp_kern.bc xdp_fp_nat64.bc
LINKED_BC := linked_xdp.bc

all: $(TARGETPROG)

$(TARGETPROG): $(LINKED_BC)
	$(llc) $^ -march=bpf -filetype=obj -o $@

$(LINKED_BC): $(BC_FILES)
	llvm-link -o $@ $^

%.bc: %.c
	$(clang) $(CLANG_FLAGS) $(CL_FLAGS) -c $< -o $@

install: all
	$(INSTALL) -D -m 644 $(TARGETPROG) $(INSTALLDIR)/$(TARGETPROG)

clean:
	rm -f *.o *.bc linked_xdp.bc
