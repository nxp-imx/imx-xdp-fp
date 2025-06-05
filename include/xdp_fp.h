/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright 2025 NXP
 */

#ifndef _XDP_FP_H
#define _XDP_FP_H
#include "types.h"

#define XDP_FP_SEC_NS   1000000000

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

#endif /* _XDP_FP_H */
