/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2022 Google LLC. */

/*
 * Test execution time of timers and related instructions.
 */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "ustats.h"

inline void barrier() { __asm__ __volatile__("": : :"memory"); }
inline void smp_mb(void) { __sync_synchronize(); }
inline void cpu_relax(void) { __asm__ __volatile__("rep; nop" ::: "memory"); }
inline void mfence(void) { __asm__ __volatile__("mfence" ::: "memory"); }

inline uint64_t rdtsc(void)
{
	uint32_t eax, edx;

	/* lfence; cpuid; rdtscp; */
	__asm__ __volatile__("rdtsc" : "=a"(eax), "=d"(edx));
	return ((uint64_t)edx) << 32 | eax;
}

inline uint64_t rdtscp(void)
{
	uint32_t eax, edx, ecx;

	/* lfence; cpuid; rdtscp; */
	__asm__ __volatile__("rdtscp" : "=a"(eax), "=c"(ecx), "=d"(edx));
	return ((uint64_t)edx) << 32 | eax;
}

/* helper for parsing arguments */
static bool is_flag(const char *val, const char *p)
{
	return (*p && *p++ == '-' && !strcmp(val, *p == '-' ? p+1 : p));
}

void run_on(pthread_t tid, int cpu)
{
	cpu_set_t aff;

	if (cpu < 0 || cpu > sysconf(_SC_NPROCESSORS_ONLN))
		return;
	CPU_ZERO(&aff);
	CPU_SET(cpu, &aff);
	pthread_setaffinity_np(tid, sizeof(aff), &aff);
}

int main(int argc, char **argv)
{
	struct ustats_cfg cfg = {
		.frac_bits = 3,
		.bits = 0,
	};
	uint64_t start, end;
	double duration = 1.0;
	int cpu = -1, i;
	struct ustats *u, *r, *rp, *c, *r_batch, *rp_batch, *c_batch;
	struct ustats *relax, *relax_batch, *mf, *mf_batch, *mb, *mb_batch;
	struct ustats *b, *b_batch;
	uint64_t sum = 0;

#define FLAG(x) is_flag(x, argv[i])
#define ARG(x) (FLAG(x) && i + 1 < argc && ++i )
	/* parse arguments */
	for (i = 1; i < argc; i++) {
		if (ARG("bits")) cfg.frac_bits = 7 & strtol(argv[i], NULL, 0);
		else if (ARG("duration")) duration = strtod(argv[i], NULL);
		else if (ARG("cpu")) cpu = strtol(argv[i], NULL, 0);
		else errx(EINVAL, "invalid flag %s", argv[i]);
	}
	run_on(pthread_self(), cpu);
	u = ustats_new("test_timers", cfg);
	r = ustats_new_table(u, "rdtsc_1");
	r_batch = ustats_new_table(u, "rdtsc_100");
	rp = ustats_new_table(u, "rdtscp_1");
	rp_batch = ustats_new_table(u, "rdtscp_100");
	c = ustats_new_table(u, "clock_gettime_1");
	c_batch = ustats_new_table(u, "clock_gettime_100");
	relax = ustats_new_table(u, "relax_1");
	relax_batch = ustats_new_table(u, "relax_100");
	mf = ustats_new_table(u, "mfence_1");
	mf_batch = ustats_new_table(u, "mfence_100");
	mb = ustats_new_table(u, "smp_mb_1");
	mb_batch = ustats_new_table(u, "smp_mb_100");
	b = ustats_new_table(u, "barrier_1");
	b_batch = ustats_new_table(u, "barrier_100");
#define TEST(u, f) { uint64_t t = ustats_now(); f; ustats_record(u, ustats_now() - t); }
#define REP10(f) { f; f; f; f; f; f; f; f; f; f; }
#define TEST100(u, f) TEST(u, {REP10(REP10(f)) })
	start = ustats_now();
	end = start + duration * 1e9;
	while (ustats_now() < end) {
		TEST(r, {sum += rdtsc();});
		TEST100(r_batch, { sum += rdtsc();});
		TEST(rp, {sum += rdtscp();});
		TEST100(rp_batch, {sum += rdtscp();});
		TEST(c, {sum += ustats_now();});
		TEST100(c_batch, { sum += ustats_now();});
		TEST(relax, {cpu_relax();});
		TEST100(relax_batch, {cpu_relax();});
		TEST(mf, {mfence();});
		TEST100(mf_batch, {mfence();});
		TEST(mb, {smp_mb();});
		TEST100(mb_batch, {smp_mb();});
		TEST(b, {barrier();});
		TEST100(b_batch, {barrier();});
	}
	(void)sum;
	ustats_control(u, "print_tables");
	return 0;
}
