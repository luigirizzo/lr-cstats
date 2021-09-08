/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 Google LLC. */

/*
 * kstats, collect samples and export distributions through debugfs
 *
 * CREATE OBJECT:
 *	struct kstats *key = kstats_new("some_name", 3);
 *
 * ADD A SAMPLE:
 *	u64 dt = ktime_get_ns();	// about 20ns
 *	<code to instrument>
 *	dt = ktime_get_ns() - t;	// about 20ns
 *	kstats_record(key, dt);		// 5ns hot cache, 250ns cold
 *
 * SHOW DATA:
 *	cat /sys/kernel/debug/kstats/some_name
 *
 *	...
 *	slot 12  CPU  0    count      764 avg       12 p 0.011339
 *	slot 12  CPU  1    count      849 avg       12 p 0.011496
 *	slot 12  CPU  2    count      712 avg       12 p 0.009705
 *	...
 *	slot 12  CPU  243  count        1 avg       12 p 0.000097
 *	slot 12  CPUS 256  count    19977 avg       12 p 0.006153
 *	...
 *
 * Besides manual code annotations, the following two commands add and remove
 * tracing of the execution time of a function or a section of code, see more
 * details later in this file:
 *
 *	echo "trace some_function" > /sys/kernel/debug/kstats/_control
 *	echo "remove some_function" > /sys/kernel/debug/kstats/_control
 */

#include <linux/kstats.h>
#include <linux/mm.h>
#include <linux/module.h>
/* About percpu: http://books.gigatux.nl/mirror/kerneldevelopment/0672327201/ch11lev1sec11.html
 * May be useful: https://stackoverflow.com/questions/16978959/how-are-percpu-pointers-implemented-in-the-linux-kernel*/
#include <linux/percpu.h>
#include <linux/sched/clock.h>	// local_clock
#include <linux/seq_file.h>
#include <linux/slab.h>
/* About DebugFS: https://www.kernel.org/doc/html/latest/filesystems/debugfs.html */
#include <linux/debugfs.h>

/* 0 : local_clock, 1: ktime_get_ns, 2: cycles, 3: instr, 4-7: perf0-3 */
static int ctr_mode;
module_param(ctr_mode, int, 0644);
u64 kstats_ctr(void)
{
	switch ((u32)ctr_mode & 7) {
	default: return local_clock();
	/* Doc ktime_get_ns: https://www.kernel.org/doc/html/latest/core-api/timekeeping.html?highlight=ktime_get_ns#c.ktime_get_ns */
	case 1: return ktime_get_ns();
	case 2: return kstats_rdpmc(0x40000000); /* wrmsr 0x38d 0x1 */
	case 3: return kstats_rdpmc(0x40000001); /* wrmsr 0x38d 0x10 */
	case 4: return kstats_rdpmc(0);	/* wrmsr 0x186 0x42xxyy */
	case 5: return kstats_rdpmc(1); /* wrmsr 0x187 0x42xxyy */
	case 6: return kstats_rdpmc(2); /* wrmsr 0x188 0x42xxyy */
	case 7: return kstats_rdpmc(3); /* wrmsr 0x189 0x42xxyy */
	}
}

/*
 * Values are 64 bit unsigned and are accumulated per cpu, in one bucket for
 * each power of 2. Each bucket is further subdivided in 2^frac_bits slots.
 * The range for each slot is 2^-frac_bits of the base value for the bucket.
 */
#define BUCKETS	64	/* Total powers of 2 */

/* For large values, sum is scaled to reduce the chance of overflow */
#define SUM_SCALE 20

/* Internal names start with ks_, external ones with kstats_ */

struct ks_slot {
	u64 samples;
	u64 sum;
};

struct kstats {
	u16 n_slots;		/* typically BUCKETS * 2^frac_bits + 2 */
	u8 frac_bits;
	u8 frac_mask;		/* 2^frac_bits - 1 */
	bool active;		/* recording status */
	struct ks_slot __percpu *slots;
	struct dentry *entry;	/* debugfs entry */
};

static void ks_print(struct seq_file *p, int slot, int cpu, u64 sum,
		     u64 tot, unsigned long samples, unsigned long avg)
{
	unsigned long frac = (tot == 0) ? 0 : ((sum % tot) * 1000000) / tot;

	seq_printf(p,
		   "slot %-3d CPU%c %-4d count %8lu avg %8lu p %c.%06lu %8lu\n",
		   slot, cpu == nr_cpu_ids ? 'S' : ' ', cpu,
		   samples, avg, sum == tot ? '1' : '0', frac, (unsigned long)sum);
}

/* Helpers for user-created nodes via _control */
static int ks_list_nodes(struct seq_file *p);
static int ks_control_write(char *buf, int ret);
static bool ks_delete_nodes(const char *name);

/* Read handler */
static int ks_show_entry(struct seq_file *p, void *v)
{
	u32 slot, cpu;
	struct ks_slot *slots, *cur;
	/* See kstats_new (debugfs_create_file invocation) to understand
	 * when is ks initialised */
	struct kstats *ks = p->private;
	u64 *partials, *totals, grand_total = 0;
	const size_t rowsize = ks ? ks->n_slots * sizeof(struct ks_slot) : 0;

	if (!ks)
		return ks_list_nodes(p);
	if (!rowsize)
		return 0;
	/*
	 * Counters are updated while we read them, so make a copy first.
	 * kvzalloc'ed memory contains three areas:
	 *
	 *   slots:	[ nr_cpu_ids ][ ks->n_slots ](struct ks_slot)
	 *   partials:	[ nr_cpu_ids ](u64)
	 *   totals:	[ nr_cpu_ids ](u64)
	 */
	/* about kvzalloc: https://lwn.net/Articles/711653/ */
	slots = kvzalloc(nr_cpu_ids * (rowsize + 2 * sizeof(u64)), GFP_KERNEL);
	if (!slots)
		return -ENOMEM;
	partials = (u64 *)(slots + ks->n_slots * nr_cpu_ids);
	totals = partials + nr_cpu_ids;
	/* Copy data and compute counts totals (per-cpu and grand_total).
	 * These values are needed to compute percentiles.
	 */
	/* about for_each_possible_cpu: https://stackoverflow.com/questions/15636214/how-is-for-each-possible-cpu-expanded-in-cpufreq-c-file */
	for_each_possible_cpu(cpu) {
		cur = slots + ks->n_slots * cpu;
		/* explain details about cpu specific data: https://www.kernel.org/doc/html/latest/core-api/this_cpu_ops.html */
		memcpy(cur, per_cpu_ptr(ks->slots, cpu), rowsize);
		for (slot = 0; slot < ks->n_slots; slot++)
			totals[cpu] += cur[slot].samples;
		grand_total += totals[cpu];
	}

	/* Second pass, produce individual lines */
	for (slot = 0; slot < ks->n_slots; slot++) {
		u64 n, samples = 0, sum = 0, samples_cumulative = 0;
		u32 bucket = slot >> ks->frac_bits;
		u32 sum_shift = bucket < SUM_SCALE ? 0 : bucket - SUM_SCALE;

		for_each_possible_cpu(cpu) {
			cur = slots + ks->n_slots * cpu;
			sum += cur[slot].sum;
			n = cur[slot].samples;
			samples += n;
			partials[cpu] += n;
			samples_cumulative += partials[cpu];
			if (n == 0)
				continue;
			ks_print(p, slot, cpu, partials[cpu], totals[cpu], n,
				 (cur[slot].sum / n) << sum_shift);
		}
		if (samples == 0)
			continue;
		ks_print(p, slot, nr_cpu_ids, samples_cumulative, grand_total,
			 samples, (sum / samples) << sum_shift);
	}
	kvfree(slots);
	return 0;
}

static ssize_t ks_write(struct file *fp, const char __user *user_buffer,
			size_t count, loff_t *position)
{
	struct inode *ino = fp->f_inode;
	/* See kstats_new for origin of ks */
	struct kstats *ks = ino ? ino->i_private : NULL;
	char buf[256] = {};
	ssize_t ret;
	u32 cpu;

	if (count >= sizeof(buf) - 1)
		return -EINVAL;
	/* about simple_write_to_buffer: https://www.kernel.org/doc/html/v5.6/filesystems/api-summary.html?highlight=simple_write_to_buffer#c.simple_write_to_buffer
	 * More info and vs copy_{from,to}_user: https://stackoverflow.com/questions/62461312/simple-read-from-buffer-simple-write-to-buffer-vs-copy-to-user-copy-from-user */
	ret = simple_write_to_buffer(buf, sizeof(buf),
				     position, user_buffer, count);
	if (ret < 0)
		return ret;
	/* Trim final newline if any */
	/* Pay attention here! More than one newline may be present! */
	if (count > 0 && buf[count - 1] == '\n')
		buf[count - 1] = '\0';

	/* This branch is chosen if no data is associated with this file */
	if (ks == NULL)
		return ks_control_write(buf, ret);

	if (!strcasecmp(buf, "START")) {
		ks->active = 1;
	} else if (!strcasecmp(buf, "STOP")) {
		ks->active = 0;
	} else if (!strcasecmp(buf, "RESET")) {
		for_each_possible_cpu(cpu) {
			memset(per_cpu_ptr(ks->slots, cpu), 0,
			       ks->n_slots * sizeof(struct ks_slot));
		}
	} else {
		ret = -EINVAL;
	}
	/* TODO: add another command to turn off and deallocate memory. */
	return ret;
}

static int ks_open(struct inode *inode, struct file *f)
{
	/* about the seq_file interface: https://www.kernel.org/doc/html/latest/filesystems/seq_file.html */
	return single_open(f, ks_show_entry, inode->i_private);
}

static const struct file_operations ks_file_ops = {
	.owner = THIS_MODULE,
	.open = ks_open,
	.release = single_release,
	.read = seq_read,
	.write = ks_write,
	.llseek = seq_lseek,
};

static struct dentry *ks_root;	/* kstats root in debugfs */

static int __init ks_init(void)
{
	printk("Loading kstats module...");
	/* Warning! Missing error handling!
	 * ks_control_write shows how to use IS_ERR_OR_NULL and PTR_ERR
	 * to recognise pointer errors */
	/* Doc debugfs_create_dir: https://www.kernel.org/doc/htmldocs/filesystems/API-debugfs-create-dir.html */
	ks_root = debugfs_create_dir("kstats", NULL);
	/* Doc debugfs_create_file: https://www.kernel.org/doc/htmldocs/filesystems/API-debugfs-create-file.html */
	debugfs_create_file("_control", 0644, ks_root, NULL, &ks_file_ops);
	return 0;
}

static void __exit ks_exit(void)
{
	ks_delete_nodes(NULL);
	debugfs_remove_recursive(ks_root);
}

/* Run as soon as possible, but after debugfs, which is in core_initcall */
postcore_initcall(ks_init);
module_exit(ks_exit);
MODULE_LICENSE("GPL");

/* User API: kstats_new(), kstats_delete(), kstats_record() */

struct kstats *kstats_new(const char *name, u8 frac_bits)
{
	struct kstats *ks = NULL;
	const char *errmsg = "";

	if (IS_ERR_OR_NULL(ks_root)) {
		errmsg = "ks_root not set yet";
		goto error;
	}

	if (frac_bits > 5) {
		/* About pr_info: https://www.kernel.org/doc/html/latest/core-api/printk-basics.html */
		pr_info("fractional bits %d too large, using 3\n", frac_bits);
		frac_bits = 3;
	}
	ks = kzalloc(sizeof(*ks), GFP_KERNEL);
	if (!ks)
		return NULL;
	ks->active = 1;
	ks->frac_bits = frac_bits;
	ks->frac_mask = (1 << frac_bits) - 1;
	ks->n_slots = ((BUCKETS - frac_bits + 1) << frac_bits) + 1;

	/* Add one extra bucket for user timestamps */
	ks->slots = __alloc_percpu((1 + ks->n_slots) * sizeof(struct ks_slot),
				   sizeof(u64));
	if (!ks->slots) {
		errmsg = "failed to allocate pcpu";
		goto error;
	}

	/* 'ks' is saved in the inode (entry->d_inode->i_private). */
	ks->entry = debugfs_create_file(name, 0444, ks_root, ks, &ks_file_ops);
	/* About __module_get: https://www.kernel.org/doc/htmldocs/kernel-hacking/routines-module-use-counters.html */
	__module_get(THIS_MODULE);
	return ks;

error:
	pr_info("kstats: '%s' error %s\n", name, errmsg);
	kstats_delete(ks);
	return NULL;
}
/* About EXPORT_SYMBOL: https://lkw.readthedocs.io/en/latest/doc/04_exporting_symbols.html*/
EXPORT_SYMBOL(kstats_new);

void kstats_delete(struct kstats *ks)
{
	if (!ks)
		return;
	debugfs_remove(ks->entry);
	if (ks->slots)
		free_percpu(ks->slots);
	*ks = (struct kstats){};
	kfree(ks);
	/* See __module_get in kstats_new */
	module_put(THIS_MODULE);
}
EXPORT_SYMBOL(kstats_delete);

void kstats_record(struct kstats *ks, u64 val)
{
	u32 bucket, slot;

	if (!ks || !ks->active)
		return;
	/* The leftmost 1 selects the bucket, subsequent frac_bits select
	 * the slot within the bucket. fls returns 0 when the argument is 0.
	 */
	/* About fls64: https://www.kernel.org/doc/htmldocs/kernel-api/API-fls64.html */
	bucket = fls64(val >> ks->frac_bits);
	slot = bucket == 0 ? val :
		((bucket << ks->frac_bits) |
		 ((val >> (bucket - 1)) & ks->frac_mask));

	/* Use the last slot on overflow if BUCKETS < 64 */
	if (slot > ks->n_slots - 2)
		slot = ks->n_slots - 1;

	/* preempt_disable makes sure samples and sum modify the same slot.
	 * this_cpu_add() uses a non-interruptible add to protect against
	 * hardware interrupts which may call kstats_record.
	 */
	preempt_disable();
	this_cpu_add(ks->slots[slot].samples, 1);
	this_cpu_add(ks->slots[slot].sum,
		     bucket < SUM_SCALE ? val : (val >> (bucket - SUM_SCALE)));
	preempt_enable();
}
EXPORT_SYMBOL(kstats_record);

/*
 * The following code supports runtime monitoring of the execution time of
 * a block of code (a function, a section between two function entry points
 * or tracepoints) with the following command:
 *
 * echo "trace S bits B start X end Y" > /sys/kernel/debug/kstats/_control
 *
 *    creates node /sys/kernel/debug/kstats/S, traces time between X and Y
 *    with 2^B buckets. Arguments after S are optional, X defaults to S,
 *    bits defaults to 3, end defaults to empty. X and Y can be function names
 *    or __tracepoint_T where T is a tracepoint name.
 *
 *    It also creates a second node /sys/kernel/debug/kstats/GAP-S that traces
 *    the time between end and start of subsequent calls to the function on
 *    the same CPU.
 *
 * echo "remove S" > /sys/kernel/debug/kstats/_control
 *
 *    removes the two /sys/kernel/debugfs/kstats nodes, S and GAP-S
 *
 * The code uses 3 different methods to track start and end of the block:
 *
 * 1. if end is not specified, uses kretprobe to collect timestamps around
 *    calls to function X.
 *
 * 2. if end != start, use kprobe to collect timestaps in the two places.
 *    Only meaningful when the two functions uniquely identify a code path.
 *
 * 3. if names have the form __tracepoint_XXX, collect timestamps at the
 *    two tracepoints.
 *
 * Metric collection through k[ret]probes or tracepoints is very convenient
 * but much more intrusive and less accurate than manual annotation: this is
 * because those hooks involve several out of line code and memory accesses,
 * particularly expensive when not in cache.
 * On a 2020 server-class x86 CPU, tracing a function with kretprobe adds
 * ~250ns with hot cache, 1500+ns with cold cache; an empty functions reports
 * a minimum time of ~90ns with hot cache, 500ns with cold cache.
 */

#include <linux/kprobes.h>
#include <linux/tracepoint.h>

/* Manually added entries are in a list protected by ks_mutex */
static LIST_HEAD(ks_user_nodes);
static DEFINE_MUTEX(ks_mutex);

/* Manually added nodes */
enum node_type { KSN_NONE = 0, KSN_KPROBE, KSN_RETPROBE, KSN_TRACEPOINT };
struct ks_node {
	struct kstats *ks;	/* record time for a call */
	struct kstats *ks_gap;	/* record gap between calls */
	struct list_head link;	/* Set for nodes added to the main list */
	enum node_type type;
	/* These could do in a union */
	/* WARNING! If a union is used ks_node_delete must be changed! */
	struct kprobe kp1;
	struct kprobe kp2;
	struct kretprobe kret;
	struct tracepoint *tp1;
	struct tracepoint *tp2;
	char name[0];
};

/* Address of the temporary storage for starting timestamp */
static u64 *ts_addr(struct kstats *ks)
{
	return &((this_cpu_ptr(ks->slots) + ks->n_slots + 1)->sum);
}

#if 0
/* Store value in slot if not set already */
static void ks_ts_start(struct kstats *ks, u64 value)
{
	u64 *addr = ts_addr(ks);

	if (!*addr)
		*addr = value;
}

/* Record value if previous was non zero */
static void ks_ts_record(struct kstats *ks, u64 value)
{
	u64 *addr = ts_addr(ks);

	if (*addr) {
		kstats_record(ks, value - *addr);
		*addr = 0;
	}
}
#endif

/*
 * Method 3, tracepoints. The first argument of the tracepoint callback
 * comes from tracepoint_probe_register, others as defined in the proto.
 */
static int ks_tp_start(struct ks_node *cur, u64 *data)
{
	u64 now;

	preempt_disable();
	now = ktime_get_ns();
	if (*data && cur->ks_gap)
		kstats_record(cur->ks_gap, now - *data);
	*data = now;
	preempt_enable();
	return 0;
}

static int ks_tp_end(struct ks_node *cur, u64 *data)
{
	u64 now;

	preempt_disable();
	now = ktime_get_ns();
	if (*data) /* should be true */
		kstats_record(cur->ks, now - *data);
	*data = cur->ks_gap ? now : 0;
	preempt_enable();
	return 0;
}

/* Method 1: kretprobe, the start timestamp is in ri->data */
static int ks_kretp_start(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	/* Very tricky code!
	 * See here for ri->rp: https://www.kernel.org/doc/html/latest/trace/kprobes.html#register-kretprobe
	 * and here for container_of: https://www.kernel.org/doc/html/latest/driver-api/basics.html?highlight=container_of#c.container_of_safe
	 * More info for container_of: https://www.linuxjournal.com/files/linuxjournal.com/linuxjournal/articles/067/6717/6717s2.html */
	return ks_tp_start(container_of(ri->rp, struct ks_node, kret),
			   (void *)(ri->data));
}

static int ks_kretp_end(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return ks_tp_end(container_of(ri->rp, struct ks_node, kret),
			 (void *)(ri->data));
}

/* Method 2, kprobes. The start timestamp is in the kstat */
static int ks_kprobe_start(struct kprobe *f, struct pt_regs *regs)
{
	struct ks_node *cur = container_of(f, struct ks_node, kp1);
	u64 *data;

	preempt_disable();
	data = ts_addr(cur->ks);
	if (!*data)
		*data = ktime_get_ns();
	preempt_enable();
	return 0;
}

static int ks_kprobe_end(struct kprobe *f, struct pt_regs *regs)
{
	struct ks_node *cur = container_of(f, struct ks_node, kp2);
	u64 *data;

	preempt_disable();
	data = ts_addr(cur->ks);
	if (*data) {
		kstats_record(cur->ks, ktime_get_ns() - *data);
		*data = 0;
	}
	preempt_enable();
	return 0;
}

/* Destroy a user-defined node */
static void ks_node_delete(struct ks_node *cur)
{
	if (!cur)
		return;
#ifdef CONFIG_TRACEPOINTS
	if (cur->tp2)
		tracepoint_probe_unregister(cur->tp2, ks_tp_end, cur);
	if (cur->tp1)
		tracepoint_probe_unregister(cur->tp1, ks_tp_start, cur);
	tracepoint_synchronize_unregister();
#endif
	unregister_kretprobe(&cur->kret);
	unregister_kprobe(&cur->kp1);
	unregister_kprobe(&cur->kp2);
	kstats_delete(cur->ks);
	kstats_delete(cur->ks_gap);
	kfree(cur);
}

/* Some names cannot be attached to */
static bool blacklisted(const char *name)
{
	static const char * const blacklist[] = {
		"kstats_record",
		NULL
	};
	int i;

	for (i = 0; name && blacklist[i]; i++) {
		if (!strcmp(name, blacklist[i])) {
			pr_info("%s is blacklisted\n", name);
			return true;
		}
	}
	return false;
}

static const char gap[] = "GAP-";
static char *ksn_name(struct ks_node *cur)
{
	return cur->name + sizeof(gap) - 1;
}

/* Create a new user-defined node */
static struct ks_node *ks_node_new(int n, char *argv[])
{
	static const char *tp_prefix = "__tracepoint_";
	char *name = argv[1], *start = name, *end = NULL;
	struct ks_node *cur;
	u64 bits = 3;
	int i, ret;
	bool percpu_instance = false;

	if (!strncmp(name, "pcpu:", 5)) {
		name += 5;
		percpu_instance = true;
		start = name;
	}

	/* 'arg value' pairs may override defaults */
	for (i = 2; i < n - 1; i += 2) {
		if (!strcasecmp(argv[i], "bits")) {
			if (kstrtou64(argv[i + 1], 0, &bits) || bits > 4) {
				pr_info("invalid bits %d\n", (int)bits);
				break;
			}
		} else if (!strcasecmp(argv[i], "start")) {
			start = argv[i + 1];
		} else if (!strcasecmp(argv[i], "end")) {
			end = argv[i + 1];
		} else {
			break;
		}
	}
	if (i != n)
		return ERR_PTR(-EINVAL);

	cur = kzalloc(sizeof(*cur) + strlen(name) + sizeof(gap), GFP_KERNEL);
	if (!cur) {
		pr_info("%s: no memory to add %s\n", __func__, name);
		return ERR_PTR(-ENOMEM);
	}
	strcpy(ksn_name(cur), name);
	if (blacklisted(start) || blacklisted(end))
		return ERR_PTR(-EINVAL);

	cur->ks = kstats_new(name, bits);
	if (!cur->ks)
		goto fail;

	if (!end || !*end) {
		/* try to create an entry with the gap between calls */
		memcpy(cur->name, gap, sizeof(gap) - 1);
		cur->ks_gap = kstats_new(cur->name, bits);

		cur->kret.entry_handler = ks_kretp_start;
		cur->kret.handler = ks_kretp_end;
		cur->kret.data_size = sizeof(u64);
		cur->kret.kp.symbol_name = start;
#ifdef KSTATS_PERCPU
		cur->kret.percpu_instance = percpu_instance;
#endif
		mb();
		ret = register_kretprobe(&cur->kret);
		if (ret)
			goto fail;
	} else if (strncmp(start, tp_prefix, strlen(tp_prefix)) != 0) {
		pr_info("XXX use kprobe on '%s', '%s'\n", start, end);
		cur->kp2.symbol_name = end;
		cur->kp2.pre_handler = ks_kprobe_end;
		if (register_kprobe(&cur->kp2))
			goto fail;
		cur->kp1.symbol_name = start;
		cur->kp1.pre_handler = ks_kprobe_start;
		if (register_kprobe(&cur->kp1))
			goto fail;
	} else {
#if 1
		/* kallsyms_lookup_name does not exist in 5.7 and above.
		 * There is a workaround in
		 * https://github.com/zizzu0/LinuxKernelModules/blob/main/FindKallsymsLookupName.c
		 * but for the time being we do not support tracepoint.
		 */
		goto fail;
#else

#if !defined(CONFIG_TRACEPOINTS)
		goto fail;
#endif
		cur->tp1 = (void *)kallsyms_lookup_name(start);
		cur->tp2 = (void *)kallsyms_lookup_name(end);
		if (!cur->tp1 || !cur->tp2)
			goto fail;
		ret = tracepoint_probe_register(cur->tp1, ks_tp_start, cur);
		if (ret)
			goto fail;
		ret = tracepoint_probe_register(cur->tp2, ks_tp_end, cur);
		if (ret)
			goto fail;
#endif
	}
	return cur;

fail:
	ks_node_delete(cur);
	return ERR_PTR(-EINVAL);

}

static int ks_list_nodes(struct seq_file *p)
{
	struct ks_node *cur;
	const char *sep = "";

	mutex_lock(&ks_mutex);
	/* Doc list_for_each_entry: https://www.kernel.org/doc/htmldocs/kernel-api/API-list-for-each-entry.html */
	list_for_each_entry(cur, &ks_user_nodes, link) {
		seq_printf(p, "%s%s", sep, ksn_name(cur));
		sep = " ";
	}
	mutex_unlock(&ks_mutex);
	/* Pay attention to possible data races */
	seq_printf(p, "\n");
	return 0;
}

/* Split a string into words, returns number of words */
static int ks_split_command(char *s, char *words[], int count)
{
	int i = 0, n;

	for (n = 0; n < count; n++) {
		/* Skip and clear leading whitespace */
		while (s[i] && strchr(" \t\r\n", s[i]))
			s[i++] = '\0';
		words[n] = s + i; /* Tentative offset */
		/* Find end of word */
		while (s[i] && s[i] > ' ' && s[i] < 127)
			i++;
		/* Notice that if cycle break here n is not incremented despite words[n] has been modified */
		if (s + i == words[n])
			break;
	}
	return n;
}

/* Delete one/all nodes (name == NULL). Returns true if some are deleted */
static bool ks_delete_nodes(const char *name)
{
	struct ks_node *tmp, *cur;
	bool found = false;

	mutex_lock(&ks_mutex);
	list_for_each_entry_safe(cur, tmp, &ks_user_nodes, link) {
		if (name != NULL && strcmp(ksn_name(cur), name))
			continue; /* no match */
		found = true;
		list_del(&cur->link);
		ks_node_delete(cur);
	}
	mutex_unlock(&ks_mutex);
	return found;
}

static int ks_control_write(char *buf, int ret)
{
	char *args[10];	/* we don't need more than 8 */
	struct ks_node *cur;
	int n;

	/* Doc ARRAY_SIZE: https://www.kernel.org/doc/html/v4.16/driver-api/basics.html?highlight=array_size#c.ARRAY_SIZE */
	n = ks_split_command(buf, args, ARRAY_SIZE(args));
	if (n < 2 || n == ARRAY_SIZE(args))
		return -EINVAL;
	if (!strcasecmp(args[0], "remove")) {
		if (n != 2)
			return -EINVAL;
		if (!ks_delete_nodes(args[1]))
			return -ENOENT;
	} else if (!strcasecmp(args[0], "trace")) {
		cur = ks_node_new(n, args);
		if (IS_ERR_OR_NULL(cur))
			return PTR_ERR(cur);
		mutex_lock(&ks_mutex);
		list_add(&cur->link, &ks_user_nodes);
		mutex_unlock(&ks_mutex);
	} else {
		ret = -EINVAL;
	}
	return ret;
}
