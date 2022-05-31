/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 */

/*
 * ustats, collect samples and export distributions through /dev/shm
 * see ustats.h for details.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ustats.h"

#define pr_info(...)    fprintf(stderr, __VA_ARGS__)

/* Values are uint64_t and are accumulated per thread, in one bucket for
 * each power of 2. Each bucket is further subdivided in 2^frac_bits slots.
 * The range for each slot is 2^-frac_bits of the base value for the bucket.
 * For large values, sum is scaled to reduce the chance of overflow.
 */

/* Internal names start with us_, external ones with ustats_ */
struct us_slot {
	uint64_t samples;
	uint64_t sum;
};

/* Per-table information, including the root pointer */
struct ustats {
	uint8_t idle;
	uint8_t frac_bits;
	uint16_t n_slots;	/* bits * 2^frac_bits+1 */
	uint16_t frac_mask;	/* 2^frac_bits - 1 */
	uint32_t entry_size;	/* redundant */
	uintptr_t _root;
	uint64_t tid;
	char name[32];
} __attribute__ ((aligned (64)));
_Static_assert(sizeof(struct ustats) == 64, "ustats too large");
_Static_assert(offsetof(struct ustats, idle) == 0, "idle must be first");

/* struct us_root occupies the first page on file with status info */
struct us_root {
	char summary[2048];

	/* All parsing-related fields are 64 bit for ease of processing */
	uint64_t frac_bits;
	uint64_t entry_size;	/* redundant, eases computations */
	uint64_t n_slots;	/* redundant, eases computations */
	uint64_t entries;
	uint64_t active;

	int	fd;
	sem_t sema;
} __attribute__ ((aligned (4096)));

static uint16_t slots_from_bits(uint8_t frac_bits, uint8_t bits)
{
	return ((bits - frac_bits + 1) << frac_bits) + 1;
}

static uint32_t entry_size_from_slots(uint16_t slots)
{
	uint32_t sz = sizeof(struct ustats) + slots * sizeof(struct us_slot);

	return (sz + 0xfffu) & ~0xfffu;
}

static struct ustats us_from_root(const struct us_root *r)
{
	return (struct ustats){
		.frac_bits = r->frac_bits,
		.frac_mask = (1 << r->frac_bits) - 1,
		.n_slots = r->n_slots,
		.entry_size = r->entry_size
	};
}

#include "ustats_sh.h"	/* experimental, include parser in image */

/* construct a printable string in the header */
static void root_summary(struct us_root *r)
{
	snprintf(r->summary, sizeof(r->summary) - 1,
		 "#!/bin/sh"
		 "ACTIVE=%c\nN_BITS=%d\nTHREADS=%d\nN_SLOTS=%u\n"
		 "ENTRY_SIZE=%u\n%s\n",
		 r->active ? 'Y':'N', (int)r->frac_bits,
		 (int)r->entries, (int)r->n_slots, (int)r->entry_size,
		 ustats_sh);
}

static void *get_new_block(int fd, size_t sz, off_t ofs)
{
	void *ret;

	if (ftruncate(fd, sz + ofs)) {
		pr_info("ftruncate at 0x%lx failed\n", (long)(sz + ofs));
		return NULL;
	}
	ret = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, ofs);
	if (ret != MAP_FAILED) {
		if (!mlock(ret, sz)) {
			memset(ret, 0, sizeof(struct ustats));
			return ret;
		}
		munmap(ret, sz);
	}

	pr_info("%s failed, /dev/shm too small ? Try\n%s\n",
		ret == MAP_FAILED ? "mmap" : "mlock",
		"mount -o remount,size=32M tmpfs /dev/shm");
	return NULL;
}

/* User API: ustats_new() ustats_new_table() __ustats_n_record() ustats_delete() */

/* Add a new entry to the collector, extending the file as needed */
struct ustats *ustats_new_table(struct ustats *table, const char *name)
{
	struct us_root *root = (void *)((uintptr_t)table ^ table->_root);
	struct ustats *ustats = NULL;
        uint64_t new_sz, sz;

	sem_wait(&root->sema);
	sz = root->entry_size;
	new_sz = sz * (root->entries + 1) + sizeof(struct us_root);
	ustats = get_new_block(root->fd, sz, new_sz - sz);
	if (ustats) {
		root->entries++;
		*ustats = us_from_root(root);	/* inherit config from root */
		ustats->_root = (uintptr_t)root ^ (uintptr_t)ustats;
		strncpy(ustats->name, name, sizeof(ustats->name));
		ustats->name[sizeof(ustats->name) - 1] = '\0';
		if (!root->active)
			ustats_table_stop(ustats);
		root_summary(root);
	}
	sem_post(&root->sema);
	return ustats;
}

struct ustats *ustats_new(const char *name, struct ustats_cfg cfg)
{
	char *fullname = NULL;
	struct ustats tmp, *ret = NULL;
	struct us_root *r = NULL;
	int fd;
	bool is_tmpfile;
	uint32_t n; /* total slots */

	if (cfg.frac_bits > 12) {
		pr_info("frac_bits %d too large, using 3\n", cfg.frac_bits);
		cfg.frac_bits = 3;
	}
	if (cfg.bits == 0 || cfg.bits > 64)
		cfg.bits = 64;
	else if (cfg.bits < cfg.frac_bits)
		cfg.bits = cfg.frac_bits;
	n = slots_from_bits(cfg.frac_bits, cfg.bits);
	if (n > 32768) {
		pr_info("frac_bits %d bits %d slots %u too large\n",
			cfg.frac_bits, cfg.bits, n);
		return NULL;
	}

	if (cfg.name && *cfg.name)
		fullname = (void *)cfg.name;
	else
		asprintf(&fullname, "kstats_%lu-%s", (unsigned long)(getpid()), name);
	is_tmpfile = !strcmp(fullname, "tmpfile");
	fd = is_tmpfile ? fileno(tmpfile()) :
			shm_open(fullname, O_RDWR | O_CREAT | O_EXCL, 0755);
	if (fd < 0) {
		pr_info("failed to create file '%s'\n", fullname);
		goto done;
	}

	r = get_new_block(fd, sizeof(struct us_root), 0);
	if (r == NULL)
		goto done;

	memset(r, 0, sizeof(*r));
	r->fd = fd;
	r->active = true;
	r->frac_bits = cfg.frac_bits;
	r->n_slots = n;
	r->entry_size = entry_size_from_slots(r->n_slots);
	root_summary(r);
	sem_init(&r->sema, 1, 1);
	tmp = us_from_root(r);
	tmp._root = (uintptr_t)r ^ (uintptr_t)&tmp;
	ret = ustats_new_table(&tmp, name);

done:
	if (!ret) {
		if (r)
			munmap(r, sizeof(struct us_root));
		if (fd >= 0) {
			if (!is_tmpfile)
				shm_unlink(fullname);
			close(fd);
		}
	}
	if (fullname != cfg.name)
		free(fullname);
	return ret;
}

void ustats_endthread(struct ustats *table)
{
	munmap(table, table->entry_size);
}

#define fls64(x) ((x) == 0? 0 : (64 - __builtin_clzl(x)))

static inline uint8_t scale_shift(uint8_t bucket)
{
	static const uint8_t sum_scale = 20;

	return bucket < sum_scale ? 0 : bucket - sum_scale;
}

void __ustats_n_record(struct ustats *ustats, uint64_t val, uint64_t n)
{
	uint8_t bucket; // XXX larger?
	uint16_t slot;
	struct us_slot *s = (struct us_slot *)(ustats + 1);

	if (!ustats || !ustats->n_slots)
		return;
	/* The leftmost 1 selects the bucket, subsequent frac_bits select
	 * the slot within the bucket. fls returns 0 when the argument is 0.
	 */
	bucket = fls64(val >> ustats->frac_bits);
	slot = bucket == 0 ? val :
		((bucket << ustats->frac_bits) |
		 ((val >> (bucket - 1)) & ustats->frac_mask));

	/* Use the last slot on overflow if BUCKETS < 64 */
	if (slot > ustats->n_slots - 2)
		slot = ustats->n_slots - 1;

	s[slot].samples += n;
	s[slot].sum += (n * val) >> scale_shift(bucket);
}

static void us_print(int tables, int slot, int tid, uint64_t sum,
		     uint64_t tot, uint64_t samples, uint64_t avg)
{
	/* Use fixed point so it can work in the kernel */
	const uint64_t frac = (tot == 0) ? 0 : ((sum % tot) * 1000000) / tot;
	const char whole = sum == tot ? '1' : '0';
	const char *name = tid == tables ? "TABLES" : "TABLE ";

	fprintf(stdout,
		"slot %-4d %s %-4d count %8lu avg %8lu p %c.%06lu n %8lu\n",
		slot, name, tid, samples, avg, whole, frac, sum);
}

static int us_printall(const struct us_root *root, int tables, bool no_summary)
{
	/*
	 * Counters are updated while we run, so make a copy first,
	 * only using actual entries, and followed by an overall table:
	 *
	 *   slots:	[ tables ][ n ](struct us_slot)
	 *   all:	          [ n ](struct us_slot)
	 *		(this is an extra table with the sum of all)
	 */
	const int n = root->n_slots, rowsize = n * sizeof(struct us_slot);
	/* After root, per-thread entries are preceded by a struct ustats */
	const char *tid_entries = (const char *)(root + 1) + sizeof(struct ustats);
	uint64_t grand_total = 0;
	int slot, tid;
	struct us_slot *all, *slots = calloc(1, (tables + 1) * rowsize);

	if (!slots) {
		pr_info("Cannot allocate temp buffer\n");
		return -1;
	}
	all = slots + tables * n;
	for (tid = 0; tid <= tables; tid++) {
		uint64_t sum = 0, tot = 0;
		struct us_slot *cur = slots + tid * n;
		const char *name = ((struct ustats *)tid_entries)[-1].name;

		if (tid == tables) {
			if (no_summary)
				break;
			name = "SUMMARY";
			tot = grand_total;
		} else {
			memcpy(cur, tid_entries, rowsize);
			tid_entries += root->entry_size; /* next entry */
			/* Accumulate in all[], and compute total samples */
			for (slot = 0; slot < n; slot++) {
				all[slot].sum += cur[slot].sum;
				all[slot].samples += cur[slot].samples;
				tot += cur[slot].samples;
			}
			grand_total += tot;
		}
		if (tot == 0)
			continue;	/* empty table */
		fprintf(stdout, "# TABLE %d: '%s'\n", tid, name);

		for (slot = 0; slot < n; slot++) {
			uint32_t scale = scale_shift(slot >> root->frac_bits);
			uint64_t avg, x = cur[slot].samples;

			if (x == 0)
				continue;
			sum += x;
			avg = ((x / 2 + cur[slot].sum) / x) << scale;
			us_print(tables, slot, tid, sum, tot, x, avg);
		}
		if (tables == 1)
			break;
	}
	free(slots);
	return 0;
}

static int us_cmdfd(int fd, const char *cmd)
{
	struct ustats *ustats;
	size_t rowsize;
	int tables;
	uint64_t sz = lseek(fd, 0, SEEK_END);
	const int mmap_mode = PROT_READ | (cmd ? PROT_WRITE : 0);
	struct us_root *root = sz ? mmap(NULL, sz, mmap_mode, MAP_SHARED, fd, 0) : NULL;
	int ret = 0;

	if (root == MAP_FAILED) {
		pr_info("cannot map size 0x%lx\n", (unsigned long)sz);
		ret = -1;
		goto done;
	}
	tables = (sz - sizeof(struct us_root)) / root->entry_size;

	if (!tables || !root->active)
		goto done;
	rowsize = root->n_slots * sizeof(struct us_slot);
	ustats = (struct ustats *)(root + 1);
	if (!cmd || !strcasecmp(cmd, "PRINT")) {
		ret = us_printall(root, tables, false);
	} else if (!strcasecmp(cmd, "PRINT_TABLES")) {
		ret = us_printall(root, tables, true);
	} else {
		char *dst;
		const int len = root->entry_size;
		int tid;

		/* Reset, stop, start require going through all nodes */
		if (!strcasecmp(cmd, "STOP")) {
			root->active = false;
			dst = (char *)ustats;
			for (tid = 0; tid < tables; tid++, dst += len)
				ustats_table_stop((struct ustats *)dst);
			root_summary(root);
		} else if (!strcasecmp(cmd, "START")) {
			root->active = true;
			dst = (char *)ustats;
			for (tid = 0; tid < tables; tid++, dst += len)
				ustats_table_start((struct ustats *)dst);
			root_summary(root);
		} else if (!strcasecmp(cmd, "RESET")) {
			dst = (char *)(ustats + 1);
			for (tid = 0; tid < tables; tid++, dst += len)
				memset(dst, 0, rowsize);
		} else {
			pr_info("Invalid command '%s'\n", cmd);
			ret = -1;
		}
	}
done:
	munmap(root, sz);
	return ret;
}


int ustats_control(const struct ustats *table, const char *cmd)
{
	const struct us_root *root;

	if (!table)
		return -1;
	root = (const void *)((uintptr_t)table ^ table->_root);
	return us_cmdfd(root->fd, cmd);
}

volatile void *static_link_shm_open_broken_otherwise = pthread_create;
int ustats_cmd(const char *name, const char *cmd)
{
	int ret;
	const int open_mode = cmd ? O_RDWR : O_RDONLY;
	int fd = shm_open(name, open_mode, 0);

	if (fd < 0) {
		pr_info("shm %s does not exist, try regular\n", name);
		fd = open(name, open_mode, 0);
		if (fd < 0) {
			pr_info("file %s does not exist, exit\n", name);
			return -1;
		}
	}
	ret = us_cmdfd(fd, cmd);
	close(fd);
	return ret;
}
