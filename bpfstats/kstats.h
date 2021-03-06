/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Google LLC. */

#ifndef __BPFSTATS_H__
#define __BPFSTATS_H__

#ifndef __bpf__
#include <linux/types.h>
#endif

/* Summary information in a global map. */
struct ks_root {
	__u8 active;
	__u8 frac_bits;		/* fractional bits */
	__u8 buckets;		/* total bits */
	__u8 percpu;		/* use per-cpu accounting */
	__u32 n_slots;
	__u32 frac_mask;
};

/* Per-cpu data is an array of ks_slot */
struct ks_slot {
	__u64 samples;
	__u64 sum;
};

/* The first few slots reserved for errors etc. */
enum { X_PREV_SAMPLE = 0, X_ENOSLOT, X_ENOPREV, X_ENOBITS, X_ENODATA,
	X_FIRST_BUCKET };

/* Large samples are scaled to avoid overflow and keep fixed precision */
static __always_inline __u8 scale_shift(__u8 bucket)
{
	const int precision = 20; /* allow 2^44 samples before overflow */

	return bucket < precision ? 0 : bucket - precision;
}

#endif /* __BPFSTATS_H__ */
