CFLAGS += -Wall -Werror -O3 -g

LDLIBS += -lrt -lpthread
OBJS = ustats.o ustats_main.o
PROGS = ustats-print

all: $(PROGS)

ustats-print: ustats_main.o ustats.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ustats.o : ustats_sh.h
ustats_sh.h : ustats.sh
	xxd -i $^ $@
$(OBJS): ustats.h Makefile

.PHONY: samples
samples:
	cd samples && make

clean:
	-rm $(OBJS) $(PROGS) ustats_sh.h
	cd samples && make clean
