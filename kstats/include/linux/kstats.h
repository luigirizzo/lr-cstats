/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Google LLC. */

#ifndef _LINUX_KSTATS_H
#define _LINUX_KSTATS_H

#include <linux/types.h>

/*
 * Helper to collect and report kernel metrics. Use as follows:
 *
 * - creates a new debugfs entry in /sys/kernel/debug/kstats/foo
 *   to collect the metric, accumulating samples in 2^frac_bits slots
 *   per power of 2, either of these
 *
 *	struct kstats *key = kstats_new("foo", frac_bits);
 *	struct kstats_cfg { .name = "bar", .entry_size = 18, .entries=200};
 *	struct kstats *key2 = kstats2_new("foo", &cfg};
 *
 * - add instrumentation around code:
 *
 *	u64 dt = ktime_get_ns();	// about 20ns
 *	<section of code to measure>
 *	dt = ktime_get_ns() - dt;	// about 20ns
 *	kstats_record(key, dt);		// 5ns hot cache, 300ns cold
 *
 * - read values from debugfs
 *	cat /sys/kernel/debug/kstats/foo
 *	...
 *	slot 55  CPU  0    count      589 avg      480 p 0.027613
 *	slot 55  CPU  1    count       18 avg      480 p 0.002572
 *	slot 55  CPU  2    count       25 avg      480 p 0.003325
 *	...
 *	slot 55  CPUS 28   count      814 avg      480 p 0.002474
 *	...
 *	slot 97  CPU  13   count     1150 avg    20130 p 0.447442
 *	slot 97  CPUS 28   count   152585 avg    19809 p 0.651747
 *	...
 *
 * - write to the file STOP, START, RESET... executes the corresponding action
 *
 *	echo RESET > /sys/kernel/debug/kstats/foo
 */

struct seq_file;

/* Special if frac_bits in kstats_new is 255 */
struct kstats_cfg {
	const char *is_null;	/* marker for new config */
	const char	*name;
	u32	entries_bits;	/* > 0 log */
	u16	entry_size;	/* 0: kstats, >0 log */
	u8	frac_bits;	/* only kstats */
	u8	wrap:1;
	int	(*printf)(struct seq_file *, const char *, int);
};

struct kstats;

static inline bool kstats_active(struct kstats *key)
{
	struct __inline_ks {	u32 a; bool active; };
	return key && ((struct __inline_ks *)key)->active;
}
#define KSTATS_RECORD(_ks, _val) do {	\
	if (kstats_active(_ks)) kstats_record((_ks), (_val)); } \
	while (0)

#if defined(CONFIG_KSTATS) || defined(CONFIG_KSTATS_MODULE)
/* Add an entry to debugfs. */
struct kstats *kstats_new(const char *name, u8 frac_bits);
struct kstats *kstats2_new(const struct kstats_cfg *cfg);

/* Record a sample */
void kstats_record(struct kstats *key, u64 value);
void kstats_log(struct kstats *ks, const void *src, int len);

/* Remove an entry and frees memory */
void kstats_delete(struct kstats *key);

static inline u64 kstats_rdpmc(u32 reg)
{
#if defined(__i386__) || defined(__x86_64__)
	u32 low, high;
	asm volatile("rdpmc": "=a" (low), "=d" (high): "c" (reg));
	return low | ((u64)(high) << 32);
#else
	return 0;
#endif
}

u64 kstats_ctr(void);
#else
static inline struct kstats *kstats_new(const char *name, u8 frac_bits)
{
	return NULL;
}
static inline struct kstats *kstats2_new(const struct kstats_cfg *cfg)
{
	return NULL;
}

static inline void kstats_record(struct kstats *key, u64 value) {}
static inline void kstats_log(struct kstats *key, const void *, int) {}
static inline void kstats_delete(struct kstats *key) {}
static inline u64 kstats_rdpmc(u32 reg) { return 0; }
static inline u64 kstats_ctr(void) { return 0; }
#endif

#endif /* _LINUX_KSTATS_H */
