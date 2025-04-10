/* Copyright 2019 NXP
 * NXP Confidential. This software is owned or controlled by NXP and may only be used strictly in
 * accordance with the applicable license terms.  By expressly accepting such terms or by
 * downloading, installing, activating and/or otherwise using the software, you are agreeing that
 * you have read, and that you agree to comply with and are bound by, such license terms.  If you
 * do not agree to be bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#ifndef _XDP_FP_H
#define _XDP_FP_H
#include "types.h"

#ifndef __stringify
# define __stringify(X)		#X
#endif

#ifndef __section
# define __section(NAME)						\
	__attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)					\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef __inline
# define __inline							\
	inline __attribute__((always_inline))
#endif

//#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif
//extern struct bpf_elf_map fp_modules;
//extern struct bpf_elf_map fp_globals;
//extern struct bpf_elf_map fp_stats;

#endif /* _XDP_FP_H */
