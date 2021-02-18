# lr_cstats

lr_cstats is a set of libraries to collect and report high resolution
histograms in multi-threaded programs.
At the moment it comes in the following variants:
- kstats, can be built as part of the linux kernel
- ustats, for userspace programs
- bpfstats, ebpf version of kstats to collect runtime of linux kernel functions

## Usage

Applications (kernel or user code) can declare a metric with one line:
(examples for the kernel version, `kstats`):
```
    const int frac_bits = 5; /* 2^frac_bits buckets per power of 2 */
    struct kstats *foo = kstats_new("some_name", frac_bits);
```
samples are N-bit values, aggregated in 2^frac_bits buckets for each
power of 2. Larger values go into an overflow bucket.

Example: N=5 frac_bits=2 creates the following buckets:
0 1 2 3  4 5 6 7  8-9 10-11 12-13 14-15  16-19 20-23 24-27 28-31
and values 32 and above go in the overflow bucket.

Samples are collected as follows:
```
    u64 start = get_value(); // eg ktime_get_ns()
    <code to measure>
    u64 end = get_value();
    kstats_record(foo, end - start);
```
Values can be time differences, as well as other counters e.g.
CPU performance counters, or other program metrics.

Values can be shown through `/sys/kernel/debug/kstats/`,
`/dev/shm/` or bpf maps in `/sys/fs/bpf/kstats/` e.g.
```
cat /sys/kernel/debug/kstats/some_name
ustats_print /dev/shm/kstats_*_some_name
bpfstats some_name
```
and version-specific commands to reset, stop, restart sample collection.

## Function monitoring

`kstats` also provides a way to dynamically attach to a kernel function
and record samples of the execution time of that function:
```
echo trace napi_gro_receive bits 3 > /sys/kernel/debug/kstats/_control
```
`bpfstats` implements the same functionality using eBPF, without need
to build a kernel module or build a kernel with kstats:
```
sudo ./kstats napi_gro_receive bits 3
```

For details on the various versions please see the three subdirectories.
