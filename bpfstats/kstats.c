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
 * user program to control kstats
 */

#include "kstats.h"
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <bpf/bpf.h>
#include "kstats_bpf.skel.h"

#define DBG(fmt, arg...) do { if (verbose)	\
	fprintf(stderr, "XXX %s %d: " fmt "\n",	\
		__func__, __LINE__, ## arg); } while (0)

static int verbose;
static const char *kstats_dir = "/sys/fs/bpf/kstats";

/* NOTE: non-reentrant */
static char *get_path(const char *name, const char *table)
{
	static char ret[256];
	int n = snprintf(ret, sizeof(ret), "%s/%s%s%s", kstats_dir, name,
			 table ? "/" : "", table ? : "");

	if (n < 0 || n == sizeof(ret))
		err(errno, "%s failed for '%s' '%s'\n", __func__, name, table);
	return ret;
}

/* Set the attach hook and type for a program */
static void set_hook(struct bpf_program *prog, const char *hook, int type)
{
	bpf_program__set_expected_attach_type(prog, type);
	errno = -bpf_program__set_attach_target(prog, /*vmlinux*/0, hook);
	if (!errno)
		return;
	errx(errno, "Failed to set hook '%s' type %d error %d '%s'", hook,
	     type, errno, errno == ESRCH ? "hook not found" : "unknown");
}

static void init_root_map(struct kstats_bpf *o, const struct ks_root *root)
{
	struct kstats_bpf__bss *bss;

	bss = mmap(NULL, sizeof(*bss), PROT_READ | PROT_WRITE, MAP_SHARED,
		   bpf_map__fd(o->maps.bss), 0);
	if (bss == MAP_FAILED)
		err(errno, "Cannot mmap 'bss'");
	bss->root = *root;
	munmap(bss, sizeof(*bss));
}

/* Returns the mmapped version of the root object in bss */
static struct ks_root *open_root(const char *name)
{
	struct kstats_bpf__bss *bss;

	bss = mmap(NULL, sizeof(*bss), PROT_READ | PROT_WRITE, MAP_SHARED,
		   bpf_obj_get(get_path(name, "bss")), 0);
	if (bss == MAP_FAILED)
		err(errno, "%s: Cannot mmap 'bss'", __func__);
	return &bss->root;
}

static int open_table(const char *name, const char *table,
		      uint *value_size, uint *max_entries)
{
	const char *path = get_path(name, table);
	struct bpf_map_info info = {};
	uint32_t info_len = sizeof(info);
	int fd = bpf_obj_get(path);

	if (fd < 0) {
		fprintf(stderr, "%s fail to open '%s'\n", __func__, path);
		return fd;
	}

	/* introspection */
	bpf_obj_get_info_by_fd(fd, &info, &info_len);
	if (verbose) {
		fprintf(stderr, "NAME '%s' PATH '%s'\n\ttype %d key_size %u "
			"value_size %u max_entries %u flags 0x%x\n",
			info.name, path, info.type, info.key_size,
			info.value_size, info.max_entries, info.map_flags);
		fprintf(stderr, "\tbtf_id %u btf_key_type_id %u "
			"btf_value_type_id %u\n", info.btf_id,
			info.btf_key_type_id, info.btf_value_type_id);
	}
	if (value_size)
		*value_size = info.value_size;
	if (max_entries)
		*max_entries = info.max_entries;
	return fd;
}

static void dump_one_table(const char *name, const char *table_name)
{
	close(open_table(name, table_name, NULL, NULL));
}

static void dump_tables(const char *name)
{
	dump_one_table(name, "kslots");
	dump_one_table(name, "pid_map");
	dump_one_table(name, "bss");
	dump_one_table(name, "data");
	dump_one_table(name, "rodata");
}

static void *my_alloc(size_t bytes, const char *msg)
{
	void *ret = calloc(1, bytes);

	if (!ret)
		err(errno, "Cannot allocate %lu bytes for '%s'",
		    (ulong)bytes, msg);
	return ret;
}

/* The bpf table has one row per entry, each row has one value per CPU.
 * We need the output with one row per cpu, plus one row for totals.
 * get_map() allocates memory, reads the map and transposes the matrix.
 */
static struct ks_slot *get_map(const char *name, uint *entries, uint *_cpus)
{
	uint32_t cpu, row = 0, cpus = libbpf_num_possible_cpus();
	uint value_size = 0;
	int fd = open_table(name, "kslots", &value_size, entries);
	const size_t data_len = value_size * *entries * (cpus + 1);
	struct ks_slot *data = my_alloc(data_len, "full map data");
	struct ks_slot *row_buffer = my_alloc(value_size * cpus, "row buffer");

	*_cpus = cpus;
	/* Copy tables to userspace */
	for (row = 0 ; row < *entries; row++) {
		if (bpf_map_lookup_elem(fd, &row, row_buffer))
			err(errno, "Failed to read map at row %u", row);
		/* Transpose from per-row to per-cpu */
		for (cpu = 0; cpu < cpus; cpu++)
			data[cpu * *entries + row] = row_buffer[cpu];
	}
	free(row_buffer);
	close(fd);
	return data;
}

/* reset values in the trace */
static int trace_reset(const char *name)
{
	uint value_size = 0, max_entries = 0;
	const int fd = open_table(name, "kslots", &value_size, &max_entries);
	uint32_t pos, tables = libbpf_num_possible_cpus();
	struct ks_slot *data = my_alloc(value_size * tables,
					"trace_reset buffer");
	struct ks_root *root = open_root(name);

	if (root->is_log) {
		pos = X_KS_LOG;
		if (bpf_map_lookup_elem(fd, &pos, data))
			err(errno, "Failed to read KS_LOG");
		for (int cpu = 0; cpu < tables; cpu++) {
			struct ks_log *e = (struct ks_log *)(data + cpu);
			e->is_stopped = 1;
		}
		bpf_map_update_elem(fd, &pos, data, BPF_ANY);
		for (int cpu = 0; cpu < tables; cpu++) {
			struct ks_log *e = (struct ks_log *)(data + cpu);
			e->is_stopped = 0;
			e->cons = e->prod = 0;
		}
		bpf_map_update_elem(fd, &pos, data, BPF_ANY);
	} else {
		for (pos = X_FIRST_BUCKET; pos < max_entries; pos++)
			bpf_map_update_elem(fd, &pos, data, BPF_ANY);
	}

	free(data);
	return 0;
}

static void create_dir(const char *path)
{
	struct stat buf;

	/* create the master directory in the virtual bpf file system */
	if (stat(kstats_dir, &buf) == -1 && mkdir(kstats_dir, 0755))
		err(errno, "Failed to create directory '%s'", kstats_dir);
	if (stat(path, &buf) != -1)
		errx(EEXIST, "Trace '%s' already exists.", path);
	if (mkdir(path, 0755))
		err(errno, "Failed to create directory '%s'", path);
}

static void pin_map(const struct bpf_object *obj, const char *name,
		    const char *pin_name)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
	int ret = bpf_map__pin(map, pin_name);

	if (!ret)
		return;

	err(ret, "pin map '%s' at %p returns %d\n", name, map, ret);
}

static void create_trace(const char *name, const char *begin_hook,
			 const char *end_hook, struct ks_root *root)
{
	int ret;
	const __u8 bits = root->frac_bits;
	uint max_entries;
	struct kstats_bpf *o = kstats_bpf__open(); /* open embedded bpf */

	if (!o)
		err(errno, "kstats_bpf__open failed");

	/* override attach points */
	set_hook(o->progs.START_HOOK, begin_hook, BPF_TRACE_FENTRY);
	set_hook(o->progs.END_HOOK, end_hook, BPF_TRACE_FEXIT);
	// bpf_program__set_autoload(o->progs.END_HOOK, false);

	if (root->is_log > 0) {
		if (root->n_slots == 0)
			errx(EINVAL, "n_slots must be > 0");
		printf("Programming log with %u slots\n", root->n_slots);
		goto done;
	}
	if (bits > 12)
		errx(EINVAL, "bits %d must be <= 12", bits);
	if (root->buckets == 0 || root->buckets > 64)
		root->buckets = 64;
	else if (root->buckets < bits)
		root->buckets = bits;
	root->n_slots = ((root->buckets - bits + 1) << bits) + 1;
	if (root->n_slots > 32700)
		errx(EINVAL, "n_slots %u must be <= 2100", root->n_slots);
	root->frac_mask = (1 << bits) - 1;
done:
	max_entries = root->n_slots + X_FIRST_BUCKET;
	bpf_map__set_max_entries(o->maps.kslots, max_entries);

	/* load bpf maps and program (including jitting ?) */
	ret = kstats_bpf__load(o);
	if (ret)
		err(ret, "Failed to load bpf programs");

	init_root_map(o, root);

	/* Actually attach the programs */
	ret = kstats_bpf__attach(o);
	if (ret)
		err(ret, "Failed to attach bpf programs");

	/* pin objects under /sys/fs/bpf/kstats/<name> */
	create_dir(get_path(name, NULL));

	/* pin map and programs */
	pin_map(o->obj, "kslots", get_path(name, "kslots"));
	pin_map(o->obj, "pid_map", get_path(name, "pid_map"));
	pin_map(o->obj, "kstats_b.bss", get_path(name, "bss"));
	pin_map(o->obj, "kstats_b.data", get_path(name, "data"));
	pin_map(o->obj, "kstats_b.rodata", get_path(name, "rodata"));

	/* these two fail in the syscall with -EINVAL on some machines:
	 * sys_bpf(BPF_OBJ_PIN, &attr, sizeof(attr));
	 */
	ret = bpf_link__pin(o->links.START_HOOK, get_path(name, "START_HOOK"));
	if (ret  || verbose)
		DBG("pin START_HOOK returns %d", ret);
	if (ret)
		errx(-ret, "failed to register START_HOOK");
	ret = bpf_link__pin(o->links.END_HOOK, get_path(name, "END_HOOK"));
	if (ret || verbose)
		DBG("pin END_HOOK returns %d", ret);
	if (ret)
		errx(-ret, "failed to register END_HOOK");
	kstats_bpf__destroy(o);
}

static int remove_trace(char *name)
{
	/* unlink objects and remove directory */
	int ret;

	ret = !!unlink(get_path(name, "kslots"));
	ret |= !!unlink(get_path(name, "pid_map"));
	ret |= !!unlink(get_path(name, "bss"));
	ret |= !!unlink(get_path(name, "data"));
	ret |= !!unlink(get_path(name, "rodata"));
	ret |= !!unlink(get_path(name, "START_HOOK"));
	ret |= !!unlink(get_path(name, "END_HOOK"));
	ret |= !!rmdir(get_path(name, NULL));
	return ret;
}

static void us_print(int tables, int slot, int tid, uint64_t sum,
		     uint64_t tot, uint64_t samples, uint64_t avg)
{
	/* Use fixed point so it can work in the kernel */
	const uint64_t frac = (tot == 0) ? 0 : ((sum % tot) * 1000000) / tot;
	const char whole = sum == tot ? '1' : '0';
	const char *name = tid == tables ? "TABLES" : "TABLE ";

	fprintf(stdout,
		"slot %-5d %s %-4d count %8lu  avg %8lu  p %c.%06lu  n %8lu\n",
		slot, name, tid, samples, avg, whole, frac, sum);
}

static void dump_root(const struct ks_root *cur)
{
	fprintf(stdout, "slot CFG   TABLES %-4d "
		"frac_bits %u n_slots %u frac_mask 0x%x%s\n",
		libbpf_num_possible_cpus(),
		cur->frac_bits, cur->n_slots,
		cur->frac_mask, cur->percpu ? " PERCPU" : "");
}

static int dump_log(struct ks_root *root, const char *name)
{
	uint max_entries = 0, cpu, tables;
	struct ks_slot *data = get_map(name, &max_entries, &tables);

	for (cpu = 0; cpu < tables; cpu++) {
		struct ks_slot *cur = data + max_entries * cpu;
		struct ks_log *log = (struct ks_log *)(cur + X_KS_LOG);
		uint32_t cons = log->cons, prod = log->prod;

		fprintf(stdout, "# CPU %u cons %u prod %u%s\n",
			cpu, cons, prod, log->is_stopped ? " STOP" : "");
		cur += X_FIRST_BUCKET;
		while (cons != prod) {
			fprintf(stdout, "CPU %-4d  %6d %12lu %12lu\n", cpu, cons,
				(ulong)cur[cons].samples, (ulong)cur[cons].sum);
			if (++cons >= root->n_slots)
				cons = 0;
		}
	}
	free(data);
	return 0;
}

static int dump_trace(const char *name)
{
	struct ks_root *root = open_root(name);
	uint tables, entries;
	struct ks_slot *data = get_map(name, &entries, &tables);
	const int n = entries - X_FIRST_BUCKET;  /* slots with samples */
	struct ks_slot *all = &data[tables * entries];
	uint64_t grand_total = 0;
	uint32_t slot, tid;

	dump_root(root);
	for (tid = 0; tid <= tables; tid++) {
		const struct ks_slot *cur = &data[tid * entries];

		if (tid != tables && cur[X_ENOSLOT].samples +
		    cur[X_ENOPREV].samples + cur[X_ENODATA].samples == 0)
			continue;
		fprintf(stdout, "slot ERRS  TABLE%c %-4d ENOSLOT %8lu "
			"ENOPREV %8lu ENODATA %8lu\n",
			tid == tables ? 'S' : ' ', tid,
			(ulong)cur[X_ENOSLOT].samples,
			(ulong)cur[X_ENOPREV].samples,
			(ulong)cur[X_ENODATA].samples);

		all[X_ENOSLOT].samples += cur[X_ENOSLOT].samples;
		all[X_ENOPREV].samples += cur[X_ENOPREV].samples;
		all[X_ENODATA].samples += cur[X_ENODATA].samples;
	}

	if (root->is_log)
		return dump_log(root, name);

	/* First pass, compute totals */
	all = &data[tables * entries + X_FIRST_BUCKET];
	for (tid = 0; tid <= tables; tid++) {
		const struct ks_slot *cur;
		unsigned long sum, tot;

		if (tid == tables) {
			tot = grand_total;
			cur = all;
		} else {
			cur = &data[tid * entries + X_FIRST_BUCKET];
			tot = 0;
			for (slot = 0; slot < n; slot++) {
				all[slot].sum += cur[slot].sum;
				all[slot].samples += cur[slot].samples;
				tot += cur[slot].samples;
			}
			grand_total += tot;
		}
		if (tot == 0)
			continue;	/* empty table */

		if (0)
			fprintf(stdout, "# TABLE%c %-4d samples %8lu\n",
				tid == tables ? 'S' : ' ', tid, tot);

		sum = 0;
		for (slot = 0; slot < n; slot++) {
			uint32_t bucket = slot >> root->frac_bits;
			const uint scale = scale_shift(bucket);
			uint64_t avg, x = cur[slot].samples;

			if (x == 0)
				continue;
			sum += x;
			avg = ((x / 2 + cur[slot].sum) / x) << scale;
			us_print(tables, slot, tid, sum, tot, x, avg);
		}
	}
	free(data);
	return 0;
}

static int list_active_traces(void)
{
	struct dirent *dir;
	DIR *d = opendir(kstats_dir);

	if (!d)
		return 1;
	while ((dir = readdir(d)) != NULL) {
		if (strcmp(dir->d_name, ".") && strcmp(dir->d_name, ".."))
			printf("%s\n", dir->d_name);
	}
	closedir(d);
	return 0;
}

static const char * const helpmsg[] = {
	"kstats - histogram of kernel function runtime using ebpf.",
	"Usage:",
	"\tkstats list|-l # show existing tables (ie traced function)",
	"\t# Use the following to show traceble functions:\n"
	"\tbpftool btf dump file /sys/kernel/btf/vmlinux | "
		"awk -F \"'\" '/FUNC.*linkage/ {print $2}' | sort | less",
	"\tkstats NAME	# show data for the named table",
	"\tkstats NAME remove|reset|start|stop # control operation for table",
	"\tkstats NAME [bits B] [buckets N] [begin X] [end Y] [percpu] "
			"[active] # create",
	"\t\tNAME : name of the trace/function being traced",
	"\t\tB : fractional bits per power of 2 [max 3]",
	"\t\tN : buckets (max value is 2^N, 0..64)",
	"\t\tX : begin hook [default NAME]",
	"\t\tY : end hook [default X]",
	NULL
};

static void usage(int err)
{
	const char * const * msg;

	for (msg = helpmsg; *msg; msg++)
		fprintf(stderr, "%s\n", *msg);
	exit(err);
}

static int my_bpf_print(enum libbpf_print_level lvl, const char *fmt,
			va_list args)
{
	return (verbose || lvl != LIBBPF_DEBUG) ?
			vfprintf(stderr, fmt, args) : 0;
}

int main(int argc, char *argv[])
{
	struct ks_root root = { .frac_bits = 3, .buckets = 64, .active = 1 };
	char *name, *begin_hook = NULL, *end_hook = NULL;
	int i = 1;

	libbpf_set_print(my_bpf_print); /* set printf function for libbpf */

	if (i < argc && !strcmp(argv[i], "-v")) {
		verbose = 1;
		i++;
	}
	if (i >= argc)
		usage(EINVAL);
	name = argv[i++];
	if (i == argc) {
		if (!strcasecmp(name, "list") || !strcmp(name, "-l"))
			return list_active_traces();
		return -dump_trace(name);
	}

	if (i + 1 == argc) {
		char *arg = argv[i];

		dump_tables(name);
		if  (!strcmp(arg, "remove")) {
			return remove_trace(name);
		} else if (!strcmp(arg, "start")) {
			open_root(name)->active = 1;
		} else if (!strcmp(arg, "stop")) {
			open_root(name)->active = 0;
		} else if (!strcmp(arg, "reset")) {
			return trace_reset(name);
		} else {
			warnx("Invalid command '%s'", arg);
			usage(EINVAL);
		}
		return 0;
	}
	/* arguments can be in any order. Expect argv[argc] == NULL */
	for (; i < argc; i++) {
		uint val;
		char *arg = argv[i];

		if (!strcmp(arg, "bits")) {
			sscanf(argv[++i], "%u", &val);
			root.frac_bits = val;
			root.is_log = 0;
		} else if (!strcmp(arg, "buckets")) {
			sscanf(argv[++i], "%u", &val);
			if (val > 64)
				errx(EINVAL, "buckets %u max 64n", val);
			root.buckets = val;
			root.is_log = 0;
		} else if (!strcmp(arg, "entries")) {
			sscanf(argv[++i], "%u", &val);
			root.n_slots = val;
			root.is_log = 1;
		} else if (!strcmp(arg, "wrap")) {
			root.is_log = 1;
			root.no_wrap = 0;
		} else if (!strcmp(arg, "nowrap")) {
			root.is_log = 1;
			root.no_wrap = 1;
		} else if (!strcmp(arg, "stop") || !strcmp(arg, "stopped")) {
			root.active = 0;	/* initial mode */
		} else if (!strcmp(arg, "percpu") || !strcmp(arg, "pcpu")) {
			root.percpu = 1;
		} else if (!strcmp(arg, "begin")) {
			begin_hook = argv[++i];
		} else if (!strcmp(arg, "end")) {
			end_hook = argv[++i];
		} else {
			warnx("invalid option '%s'", arg);
			usage(EINVAL);
		}
	}
	begin_hook = begin_hook ? : name;
	end_hook = end_hook ? : begin_hook;
	create_trace(name, begin_hook, end_hook, &root);
	return 0;
}
