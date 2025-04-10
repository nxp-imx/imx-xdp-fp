# Default values
CC ?= gcc
ARCH ?= arm64
llc ?= llc
clang ?= clang
PREFIX ?= ./install
USE_LOCAL_LIBS ?= 0

ifeq ($(KERNEL_HEADERS),)
$(error KERNEL_HEADERS is not set. please define it as the path of kernel installed headers)
endif

CL_FLAGS := -g -O2 -emit-llvm -target bpf -D__KERNEL__ -D__BPF__ -Wall \
	-I$(KERNEL_HEADERS)/include


C_FLAGS := -Wall \
	-I$(KERNEL_HEADERS)/include

L_FLAGS := -lzstd -lz -lelf -lbpf

ifeq ($(USE_LOCAL_LIBS),1)
CL_FLAGS +=-I./lib/usr/include/
C_FLAGS +=-I./lib/usr/include/
L_FLAGS += -L./lib/usr/lib
endif

BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/usr/lib
TARGETBIN := xdp_fp
TARGETPROG := xdp_fp_kern.o

INSTALL := install

all: $(TARGETPROG) $(TARGETBIN)
$(TARGETPROG): xdp_fp_kern.bc
	$(llc) $^ -march=bpf -filetype=obj -o $@

xdp_fp_kern.bc: xdp_fp_kern.c
	$(clang) $(CLANG_FLAGS) $(CL_FLAGS) -c $< -o $@

$(TARGETBIN): xdp_fp_user.c
	$(CC) $(CFLAGS) $(C_FLAGS) $(LDFLAGS) $< -o $@ $(L_FLAGS)

install: all
	$(INSTALL) -D -m 755 xdp_fp $(DESTDIR)$(BINDIR)/$(TARGETBIN)
	$(INSTALL) -D -m 644 $(TARGETPROG) $(DESTDIR)$(BINDIR)/$(TARGETPROG)
ifeq ($(USE_LOCAL_LIBS),1)
	$(INSTALL) -D -m 644 lib/usr/lib/libbpf.so.1 $(DESTDIR)$(LIBDIR)/libbpf.so.1
	$(INSTALL) -D -m 644 lib/usr/lib/libelf.so.1 $(DESTDIR)$(LIBDIR)/libelf.so.1
	$(INSTALL) -D -m 644 lib/usr/lib/libz.so.1 $(DESTDIR)$(LIBDIR)/libz.so.1
	$(INSTALL) -D -m 644 lib/usr/lib/libzstd.so.1 $(DESTDIR)$(LIBDIR)/libzstd.so.1
endif
clean:
	rm -f *.o
	rm -f *.bc
	rm -rf xdp_fp
