# bpfstats - histogram of kernel function runtime using ebpf

This is a bpf version of kstats, derived from
https://github.com/tommasoburlon/bpfstats
(in turn derived from my kstats)

It implements the function tracing using fentry/fexit via bpf.

Supported functions can be seen with
```
bpftool btf dump file /sys/kernel/btf/vmlinux | egrep 'FUNC.*linkage' | sort -k 2 | less
```
