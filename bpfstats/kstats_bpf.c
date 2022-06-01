/*
 *  Copyright 2021 Google LLC
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the License is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the License for the specific language governing permissions and
 *      limitations under the License.
 */

/* bpf code for bpfstats */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "kstats.h"

#define PROCESS_BUFFER_SIZE 1024

char _license[] SEC("license") = "GPL";

/* globals initialize with !0 to go in .data, otherwise they go in .bss
 *
 * Non-scalar .data were broken due to a clang bug before clang 11.0.1
 * see https://godbolt.org/z/Mnx38v struct_in_data.a
 *
 * obj->data->foo = .. assignments can also be made before __load()
 * libbpf had a bug (fixed in 0.3 or 0.2) so that
 * obj->bss->foo = .. assignments are only effective after __load()
 *
 * You can pin .rodata .bss and .data, they are maps named X.bss etc.
 * with X containing up to 8 bytes of the filename.
 */

const uint32_t this_is_rodata_testonly = 54;
uint32_t this_is_data_testonly = 54;

struct ks_root root;	/* in bss */

/* NOTE: __uint() and __type() specify what the entries are used for.
 * 'type', 'max_entries', 'key', 'value' etc are dedicated field names.
 */

/* This map stores the initial timestamp for each pid when non-percpu */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, PROCESS_BUFFER_SIZE);
	__type(key, u64);	/* pid */
	__type(value, u64);	/* timestamp */
} pid_map SEC(".maps");

/* This map stores the per-cpu slots and metadata. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);	/* overridden */
	__type(key, u32);	/*  mandatory for this type */
	__type(value, struct ks_slot);
} kslots SEC(".maps");

/* Hook on function entry, collect first timestamp */
SEC("fentry/not_a_function")
int BPF_PROG(START_HOOK /* args */)
{
	if (!root.active)
		return 0;
	if (root.percpu) {
		const u32 pos = X_PREV_SAMPLE;
		struct ks_slot *slot = bpf_map_lookup_elem(&kslots, &pos);

		if (slot)
			slot->samples = bpf_ktime_get_ns();
	} else {
		u64 pid = bpf_get_current_pid_tgid();
		/* The lookup reduces error if the element is already there */
		u64 *value = bpf_map_lookup_elem(&pid_map, &pid);
		u64 now = bpf_ktime_get_ns();

		if (value)
			*value = now;
		else
			bpf_map_update_elem(&pid_map, &pid, &now, BPF_ANY);
	}
	return 0;
}

static __always_inline u32 fls64(u64 val)
{
	u32 res = 0;

	if (val >= (1ul << 32)) { res += 32; val >>= 32; }
	if (val >= (1ul << 16)) { res += 16; val >>= 16; }
	if (val >= (1ul << 8)) { res += 8; val >>= 8; }
	if (val >= (1ul << 4)) { res += 4; val >>= 4; }
	if (val >= (1ul << 2)) { res += 2; val >>= 2; }
	if (val >= (1ul << 1)) { res += 1; val >>= 1; }
	if (val >= (1ul << 0)) { res += 1; val >>= 1; }
	return res;
}

static __always_inline int increment_error(int pos)
{
	struct ks_slot *slot = bpf_map_lookup_elem(&kslots, &pos);

	if (slot)
		slot->samples++;
	return 0;
}

#define RET_IF(cond, err) if (cond) return increment_error(err)

static __always_inline int store_log(u64 val, u64 prev)
{
	struct ks_slot *slot;
	u32 pos = X_KS_LOG;
	struct ks_log *log = bpf_map_lookup_elem(&kslots, &pos);

	RET_IF(!log, X_ENOSLOT);
	if (log->is_stopped)
		return 0;
	pos = log->prod + X_FIRST_BUCKET;
	slot = bpf_map_lookup_elem(&kslots, &pos);
	RET_IF(!slot, X_ENOSLOT);
	slot->samples = val + prev;
	slot->sum = val;
	if (root.no_wrap) {
		u32 used = log->prod - log->cons;
		if (used > root.n_slots)	/* wraparound */
			used += root.n_slots;
		if (used >= root.n_slots - 2)
			log->is_stopped = 1;
	}
	if (++log->prod >= root.n_slots)
		log->prod = 0;
	if (log->prod == log->cons) {
		if (++log->cons >= root.n_slots)
			log->cons = 0;
	}
	return 0;
}

/* Hook on function exit, read second timestamp and store delta in kstats */
SEC("fexit/not_a_function")
int BPF_PROG(END_HOOK /* args */)
{
	u64 prev, val;
	u32 pos;
	struct ks_slot *slot;

	if (!root.active)
		return 0;
	val = bpf_ktime_get_ns(); /* second timestamp */
	if (root.percpu) {
		pos = X_PREV_SAMPLE;
		slot = bpf_map_lookup_elem(&kslots, &pos);
		RET_IF(!slot, X_ENOSLOT);
		prev = slot->samples;
		slot->samples = 0ul;
	} else {
		/* retrieve previous timestamp for this pid */
		u64 pid = bpf_get_current_pid_tgid();
		u64 *pprev = bpf_map_lookup_elem(&pid_map, &pid);

		RET_IF(!pprev, X_ENOSLOT);
		prev = *pprev;
		/* Another thread may have updated the entry after we start
		 * this thread and fetch the time ?
		 */
		*pprev = 0ul;
		RET_IF(prev > val, X_ENODATA);
	}
	RET_IF(!prev, X_ENOPREV);
	val -= prev;
	if (root.is_log)
		return store_log(val, prev);

	/* calculate the logarithm with some extra digits */
	if ((val & root.frac_bits) == val) {	/* bucket is 0 */
		/* val does not need masking or scaling */
		pos = val;
	} else {
		u32 bucket = fls64(val >> root.frac_bits);

		pos = (bucket << root.frac_bits) |
			((val >> (bucket - 1)) & root.frac_mask);
		val >>= scale_shift(bucket);
	}
	if (pos > root.n_slots - 1)
		pos = root.n_slots - 1;
	pos += X_FIRST_BUCKET;
	slot = bpf_map_lookup_elem(&kslots, &pos);
	RET_IF(!slot, X_ENODATA);

	/* use atomic operation but not fundamental with per cpu HASH */
	__sync_fetch_and_add(&slot->samples, 1);
	__sync_fetch_and_add(&slot->sum, val);
	return 0;
}
