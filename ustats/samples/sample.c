/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Google LLC. */

/* Example program to use ustats. */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "ustats.h"

void *foo(void *p)
{
	uint64_t dt;
	static __thread struct ustats *table;

	table = ustats_new_table(p, pthread_self());
	fprintf(stderr, "pthread %p tid %ld table %p\n",
		(void *)pthread_self(), syscall(SYS_gettid), table);
	for (;;) {
		usleep(10000);
		dt = ustats_now();
		ustats_record(table, 0);
		ustats_record(table, ustats_now() - dt);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	struct ustats_cfg cfg = {
		.frac_bits = argc > 1 ? atoi(argv[1]) : 5,
		.bits = argc > 2 ? atoi(argv[2]) : 0,
	};
	struct ustats *t_slow = ustats_new("slow", cfg);
	struct ustats *t_fast = ustats_new("fast", cfg);
	struct ustats *t_test = ustats_new_table(t_fast, 0);
	struct ustats *t_empty = ustats_new_table(t_fast, 1);
	int i;

	for (i = 0; i < 10; i++) {
		pthread_t x;

		pthread_create(&x, NULL, foo, t_slow);
	}
	for (i = 0; i < 1000000;i++) {
		uint64_t t = ustats_now();

		ustats_record(t_test, 0);
		ustats_record(t_fast, ustats_now() - t);
		t = ustats_now();
		ustats_record(t_empty, ustats_now() - t);
		//usleep(10000);
	}
	ustats_control(t_fast, "print");
	return 0;
}
