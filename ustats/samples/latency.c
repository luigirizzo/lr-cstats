/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Google LLC. */

/* Test latency of various system calls.
 * invoke with taskset -c ... to bind threads.
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include "ustats.h"

struct mypipes {
	int rd, wr;	/* forward channel */
	int rd2, wr2;	/* reverse channel */
};
struct test_arg {
	struct ustats *us;
	struct ustats *us2;
	int count;
	struct mypipes pipes;
	int mode;
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

#define CHECK(x) if (!(x)) { fprintf(stderr, "ERRNO %d in %s:%d\n", errno, __func__, __LINE__); exit(1); }

/* Create a bidirectional channel using pipes, eventfd, socketpair or sockets */

static struct mypipes openpipe(int mode)
{
	struct mypipes ret = { -1, -1, -1, -1 };

	if (mode == 1) {
		printf("RUNNING ON A PIPE\n");
		pipe((int *)&ret.rd);
		pipe((int *)&ret.rd2);
	} else if (mode == 2) {
		printf("RUNNING ON AN EVENTFD\n");
		ret.wr = ret.rd = eventfd(0, 0);
		ret.wr2 = ret.rd2 = eventfd(0, 0);
	} else if (mode == 3 || mode == 4 || mode == 6) {
		int fd, val = 1;
		printf("RUNNING ON ipv%d\n", mode);
		if (mode == 3) {
			socketpair(AF_LOCAL, SOCK_STREAM, 0, (int *)&ret.rd);
		} else if (mode == 4) {
			struct sockaddr_in sa4 = {};

			fd = socket(AF_INET, SOCK_STREAM, 0);
			setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
			ret.wr = socket(AF_INET, SOCK_STREAM, 0);
			sa4.sin_family = AF_INET;
			sa4.sin_port = htons(9876);
			inet_pton(AF_INET6, "127.0.0.1", &sa4.sin_addr);
			bind(fd, (struct sockaddr *)&sa4, sizeof(sa4));
			listen(fd, 10);
			connect(ret.wr, (struct sockaddr *)&sa4, sizeof(sa4));
			ret.rd = accept(fd, NULL, NULL);
		} else {
			struct sockaddr_in6 sa6 = {};
			fd = socket(AF_INET6, SOCK_STREAM, 0);
			setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
			ret.wr = socket(AF_INET6, SOCK_STREAM, 0);
			sa6.sin6_family = AF_INET6;
			sa6.sin6_port = htons(9876);
			inet_pton(AF_INET6, "::1", &sa6.sin6_addr);
			bind(fd, (struct sockaddr *)&sa6, sizeof(sa6));
			listen(fd, 10);
			connect(ret.wr, (struct sockaddr *)&sa6, sizeof(sa6));
			ret.rd = accept(fd, NULL, NULL);
		}
		ret.wr2 = ret.rd;
		ret.rd2 = ret.wr;
	} else {
		printf("UNSUPPORTED MODE %d\n", mode);
	}
	printf("%s returns %d %d %d %d\n", __func__, ret.wr, ret.rd, ret.wr2, ret.rd2);
	if (ret.wr < 0 || ret.rd < 0 || ret.rd2 < 0 || ret.wr2 < 0)
		exit(1);
	return ret;
}


/* Single thread doing write, poll, read */
static void test_rw(struct test_arg *arg)
{
	struct pollfd p;
	uint64_t val = 1;	/* eventfd needs 8 bytes */
	int i;
	uint64_t t;
	arg->pipes = openpipe(arg->mode);

	for (i = 0; arg-> count < 0 || i < arg->count; i++) {
		p.fd = arg->pipes.rd;
		p.events = POLLIN;
		val = 1;
		t = ustats_now();
		CHECK(write(arg->pipes.wr, &val,  sizeof(val)) > 0);
		poll(&p, 1, -1);
		CHECK(read(arg->pipes.rd, &val, sizeof(val)) > 0);
		ustats_record(arg->us, ustats_now() - t);
	}
}

static void *eventfd_child(void *_arg)
{
	uint64_t val, ack = 1;
	int i;
	struct test_arg *arg = _arg;

	for (i = 0; arg->count < 0 || i < arg->count; i++) {
		CHECK(read(arg->pipes.rd, &val, sizeof(val)) > 0);
		ustats_record(arg->us, ustats_now() - arg->t0);
		CHECK(write(arg->pipes.wr2, &ack, sizeof(ack)) > 0);
	}
	return NULL;
}

/* two threads doing a ping pong */
static void test_pingpong(struct test_arg *arg)
{
	pthread_t child;
	void *retval;
	uint64_t ack, val = 1;
	int i;
	arg->pipes = openpipe(arg->mode);

	pthread_create(&child, NULL, eventfd_child, arg);
	for (i = 0; arg->count < 0 || i < arg->count; i++) {
		arg->t0 = ustats_now();
		CHECK(write(arg->pipes.wr, &val, sizeof(val)) > 0);
		CHECK(read(arg->pipes.rd2, &ack, sizeof(ack)) > 0);
		ustats_record(arg->us2, ustats_now() - arg->t0);
	}
	pthread_join(child, &retval);
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

#define T(name, count)	{ test_ ## name, #name, count  }

int main(int argc, char **argv)
{
	struct ustats_cfg cfg = {
		.frac_bits = 3,
		.bits = 30,
		.name = "none",
	};
	struct test_entry tests[] = {
		T(gettimeofday, 1e6),
		T(pingpong, 1e5),
		T(write, 1e6),
		T(rw, 1e5),
		{}
	};
	struct test_arg arg = {};
	int i;
	const char *opt, *want = NULL;

	arg.count = 10000;

	for (i = 1; (opt = argv[i++]);) {
		if (!strcmp(opt, "-frac_bits")) cfg.frac_bits = atoi(argv[i++]);
		if (!strcmp(opt, "-bits")) cfg.bits = atoi(argv[i++]);
		if (!strcmp(opt, "-test")) want = argv[i++];
		if (!strcmp(opt, "-mode")) arg.mode = atoi(argv[i++]);
		if (!strcmp(opt, "-count")) arg.count = atoi(argv[i++]);
	}
	fprintf(stdout, "selected '%s' frac_bits %d bits %d count %d\n",
		cfg.name, cfg.frac_bits, cfg.bits, arg.count);
	fprintf(stdout, "Enable user rdpmc with\n%s\n",
		"echo 2 > /sys/bus/event_source/devices/cpu/rdpmc");

	arg.us = ustats_new("direct", cfg);
	arg.us2 = ustats_new_table(arg.us, 2);
	for (i = 0; tests[i].fn; i++) {
		if (!strstr(want, tests[i].name)) {
			fprintf(stdout, "skip %s against '%s'\n",
				tests[i].name, want);
			continue;
		}
		ustats_control(arg.us, "reset");
		ustats_control(arg.us2, "reset");
		fprintf(stdout, "\nTESTING %s\n", tests[i].name);
		//arg.count = tests[i].cycles;
		tests[i].fn(&arg);
		ustats_control(arg.us, "print");
	}

	return 0;
}
