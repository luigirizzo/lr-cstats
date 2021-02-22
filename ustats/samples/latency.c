/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Google LLC. */

/* Test latency of various system calls.
 * invoke with taskset -c ... to bind threads.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include "ustats.h"

struct test_arg {
	struct ustats *us;
	int count;
	int fd, ack;
	uint64_t t0;
};

static void test_gettimeofday(struct test_arg *arg)
{
	uint64_t t, i;

	for (i = 0; i < arg->count;i++) {
		t = ustats_now();
		ustats_now();
		ustats_record(arg->us, ustats_now() - t);
	}
}

static void *eventfd_child(void *_arg)
{
	uint64_t i, val, ack = 1;
	struct test_arg *arg = _arg;

	for (i = 0; i < arg->count; i++) {
		read(arg->fd, &val, sizeof(val));
		ustats_record(arg->us, ustats_now() - arg->t0);
		write(arg->ack, &ack, sizeof(ack));
	}
	return NULL;
}

static void test_eventfd(struct test_arg *arg)
{
	pthread_t child;
	void *retval;
	int ret;
	uint64_t i, ack, val = 1;

	arg->fd = eventfd(0, 0);
	arg->ack = eventfd(0, 0);

	pthread_create(&child, NULL, eventfd_child, arg);
	for (i = 0; i < arg->count; i++) {
		arg->t0 = ustats_now();
		ret = write(arg->fd, &val, sizeof(val));
		read(arg->ack, &ack, sizeof(ack));
	}
	pthread_join(child, &retval);
	close(arg->fd);
	close(arg->ack);
}

static void test_write(struct test_arg *arg)
{
	FILE *f = tmpfile();
	int fd = fileno(f);
	char buf[64] = {};
	uint64_t t, i;

	for (i = 0; i < arg->count; i++) {
		buf[0] = i;
		t = ustats_now();
		write(fd, buf, 1);
		ustats_record(arg->us, ustats_now() - t);
	}
	fclose(f);
}

struct test_entry {
	void (*fn)(struct test_arg *);
	const char *name;
	uint64_t cycles;
};

#define T(name, count)	{ name, #name, count  }

int main(int argc, char **argv)
{
	struct ustats_cfg cfg = {
		.frac_bits = argc > 1 ? atoi(argv[1]) : 4,
		.bits = argc > 2 ? atoi(argv[2]) : 0,
		.name = "none",
	};
	struct ustats *us = ustats_new("direct", cfg);
	struct test_entry tests[] = {
		T(test_gettimeofday, 1e6),
		T(test_eventfd, 1e5),
		T(test_write, 1e6),
		{}
	};
	struct test_arg arg;
	int i;

	fprintf(stdout, "Enable user rdpmc with\n%s\n",
		"echo 2 > /sys/bus/event_source/devices/cpu/rdpmc");

	arg.count = 10000;
	arg.us = us;
	for (i = 0; tests[i].fn; i++) {
		ustats_control(us, "reset");
		fprintf(stdout, "\nTESTING %s\n", tests[i].name);
		arg.count = tests[i].cycles;
		tests[i].fn(&arg);
		ustats_control(us, "print");
	}

	return 0;
}
