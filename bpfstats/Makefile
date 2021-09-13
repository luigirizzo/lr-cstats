# Makefile for bpfstats
# sudo apt-get install clang	# need at least 11.0.1
# sudo apt-get install libbpf-dev # need at least 0.3 (maybe 0.2 is ok)
# sudo apt-get install bpftool	$ 5.8.14 ?
#	check version/files with dpkg -l|-L package_name
# see https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html
# https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html
#
# require also libelf, libelf-dev, libz-dev
# bpftool is installed via linux-tools-common
# 	and may require linux-tools-5.8.0-63-generic (depending on kenrel version, see "uname -r")
#	linux-tools-generic is suggested
#

BPF_SRC := kstats_bpf
CC = gcc
CLANG := clang
BPFTOOL := bpftool
LIBBPF := -lbpf
CFLAGS_LIBBPF := -I/usr/include/bpf
CFLAGS := -g -O2 -Wall -Werror $(CFLAGS_LIBBPF)
CFLAGS += -static
APP_NAME := kstats

.PHONY: all
all: $(APP_NAME)

.PHONY: clean
clean:
	rm -rf $(APP_NAME) *.o *.skel.h vmlinux.h

$(APP_NAME): kstats.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBBPF) -lz -lelf

kstats.o: kstats.c $(BPF_SRC).skel.h kstats.h
	$(CC) $(CFLAGS) -c $< -o $@

# we could live with a hand-built version of vmlinux.h, but it is more
# convenient to create it with bpftool
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_SRC).skel.h: $(BPF_SRC).o
	$(BPFTOOL) gen skeleton $< > $@

$(BPF_SRC).o: $(BPF_SRC).c kstats.h vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf $(TARGET_ARCH) -c $< -o $@
