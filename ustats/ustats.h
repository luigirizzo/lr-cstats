/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Google LLC. */

#ifndef _USTATS_H
#define _USTATS_H

/* This library can be used to collect and export per-thread histograms
 * of some samples using shared memory segments.
 * Samples are N-bit values, aggregated in 2^frac_bits buckets for each
 * power of 2. Larger values go into an overflow slot.
 * Example: bits=5, frac_bits=2 creates the following buckets:
 * 0 1 2 3  4 5 6 7  8-9 10-11 12-13 14-15  16-19 20-23 24-27 28-31
 * and values 32 and above go in the overflow bucket.
 *
 * USAGE:
 * - create first table in a shm segment (visible in /dev/shm/<pid>-foo),
 *
 *	struct ustats_cfg cfg = { .frac_bits = 3, .bits = 64 };
 *	struct ustats *table = ustats_new("foo", cfg);
 *   
 * - additional tables can be created with
 *
 *      struct ustats *table2 = ustats_new_table(table, uint64_id);
 *
 * - add instrumentation around code:
 *
 *	uint64_t dt = ustats_now();	// about 20ns
 *	<section of code to measure>
 *	dt = ustats_now() - dt;		// about 20ns
 *	ustats_record(table, dt);	// 5ns hot cache, 300ns cold
 *
 * - read values using an external utility, ./ustats-print or ustats.sh
 *
 *	./ustats-print /dev/shm/<pid>-foo
 *	...
 *	slot  55  TABLE  0    count      589 avg      480 p 0.027613
 *	slot  55  TABLE  1    count       18 avg      480 p 0.002572
 *	slot  55  TABLE  2    count       25 avg      480 p 0.003325
 *	...
 *	slot  55  TABLES 28   count      814 avg      480 p 0.002474
 *	...
 *	slot  97  TABLE  13   count     1150 avg    20130 p 0.447442
 *	slot  97  TABLES 28   count   152585 avg    19809 p 0.651747
 *	...
 *
 * - use ustats-print to STOP, START, RESET collection (for all tables;
 *   filtering can be done grepping TABLE  * or TABLES
 *
 *	./ustats-print <pid>-foo {START|STOP|RESET}
 *
 * NOTE: if /dev/shm is too small you may need to expand it
 *     mount -o remount,size=32M tmpfs /dev/shm
 */

#include <inttypes.h>
#include <time.h>

struct ustats_cfg {
	uint8_t frac_bits;
	uint8_t bits;
	const char *name;	/* override system-assigned name */
};

struct ustats;	/* opaque, first byte contains flags */

/* Create a new collector with a first table eg. for main thread. */
struct ustats *ustats_new(const char *name, struct ustats_cfg cfg);

/* Create an additional table eg for use in a separate thread */
struct ustats *ustats_new_table(struct ustats *table, const char *name);

static inline int ustats_active(const struct ustats *table)
{
	return (*(const uint8_t *)table) == 0;
}

static inline void ustats_table_start(struct ustats *table)
{
	*(uint8_t *)table = 1;
}

static inline void ustats_table_stop(struct ustats *table)
{
	*(uint8_t *)table = 0;
}
#undef __USTATS_IDLE

/* Record one sample */
#define ustats_record(table, val) ustats_n_record(table, val, 1)
/* Record one sample with weight n (i.e. n times) */
void __ustats_n_record(struct ustats *table, uint64_t value, uint64_t n);
static inline void ustats_n_record(struct ustats *table, uint64_t value, uint64_t n)
{
	if (ustats_active(table))
		__ustats_n_record(table, value, n);
}


/* Unmap a single table (data in /dev/shm is preserved) */
void ustats_endthread(struct ustats *table);

/* start/stop/reset/print. ustats_cmd() is useful for external programs, 
 * ustats_control() can be used internally since the pointer is available.
 */
int ustats_cmd(const char *name, const char *cmd);
int ustats_control(const struct ustats *table, const char *cmd);

/* Helper for timestamp collection. Some barrier is necessary */
static inline uint64_t ustats_now(void)
{
	struct timespec tv;

	asm volatile("": : :"memory");	/* or __sync_synchronize(); */
	clock_gettime(CLOCK_MONOTONIC, &tv);
	asm volatile("": : :"memory");	/* or __sync_synchronize(); */
	return tv.tv_nsec + (1000ull*1000*1000) * tv.tv_sec;
}

/* Experimental, read from performance counters or msr */
#include "lr_perf.h"
//#define ustats_now() rdpmc_now(0x40000001)	// clocks
//#define ustats_now() rdpmc_now(0x40000000)	// instr

#endif /* _USTATS_H */
