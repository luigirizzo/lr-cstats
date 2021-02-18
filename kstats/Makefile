CONFIG_KSTATS=m
obj-$(CONFIG_KSTATS) += kstats.o

BUILD_DIR=/lib/modules/$(shell uname -r)/build
CFLAGS_kstats.o += -I$(PWD)/include -DCONFIG_KSTATS

all:
	make -C $(BUILD_DIR) M=$(PWD) modules

clean:
	make -C $(BUILD_DIR) M=$(PWD) clean

