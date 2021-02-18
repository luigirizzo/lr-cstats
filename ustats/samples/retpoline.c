/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Google LLC. */

/* Retpoline test */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "ustats.h"
#include "lfsr.h"


volatile int y, z, t;
extern volatile int x;
extern void foo(void);

void (*foop)(void) = foo;

int main(int argc, char **argv)
{
	struct ustats_cfg cfg = {
		.frac_bits = argc > 1 ? atoi(argv[1]) : 4,
		.bits = argc > 2 ? atoi(argv[2]) : 0,
	};
	struct ustats *direct = ustats_new("direct", cfg);
	struct ustats *retp = ustats_new_table(direct, 0);
	int i, j;

	fprintf(stdout, "Enable user rdpmc with\n%s\n",
		"echo 2 > /sys/bus/event_source/devices/cpu/rdpmc");

	for (i = 0; i < 1000;i++) {
		uint64_t t = ustats_now();
		asm("lfence;");
		for (j = 0; j < 1000; j++) { foop(); }
		ustats_record(retp, ustats_now() - t);
		//usleep(1000);
		t = ustats_now();
		asm("lfence;");
		for (j = 0; j < 1000; j++) { foo(); }
		ustats_record(direct, ustats_now() - t);
		//usleep(1000);
	}
	fprintf(stdout, "TABLE 0 = direct, TABLE 1 = retpoline, %s\n",
		"avg is cycles per 1000 repetitions");
	ustats_control(direct, "print");
	return 0;
}
