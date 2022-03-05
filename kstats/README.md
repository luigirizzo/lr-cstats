# kstats

This is the kernel version of kstats.

## Installation

You can apply the patch to a full kernel to build it statically,
or just build it as a module, using `make` in this directory.
Make sure you have the linux headers for your kernel
```
apt-get install build-essential linux-headers-$(uname -r)
dpkg -l linux-headers-$(uname -r)
```

## Usage

For direct instrumentation of kernel code, follow the instructions
in `include/linux/kstats.h` .
An entry defined with `kstats_new("foo", n)` will appear
in `/sys/kernel/debug/kstats/foo`. Reading the file produces the current
state of the histogram, per-cpu.

To stop/start/reset collection do
`echo {start|stop|reset} > /sys/kernel/debug/kstats/foo`

For instrumentation of functions using debugfs, you can attach to kernel
functions with the syntax

```
echo trace [pcpu:]function_name [bits n] > /sys/kernel/debug/kstats/_config
echo remove function_name > /sys/kernel/debug/kstats/_config
```

See details in `kstats.c:ks_node_new()` for supported commands.
