# kstats

This is the kernel version of kstats.
You can apply the patch to a full kernel to build it statically,
or just build it as a module, using `make` in this directory.
Make sure you have the linux headers for your kernel
```
apt-get install build-essential linux-headers-$(uname -r)
dpkg -l linux-headers-$(uname -r)
```
