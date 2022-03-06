# Some sample programs for ustats
CFLAGS += -Wall -Werror -O3 -g -static -I ..

# clang flags for retpoline
CC=clang
#CFLAGS += -mretpoline-external-thunk

# gcc flags for retpoline
# choices are keep, thunk, think-extern
#CC=gcc
#CFLAGS += -mindirect-branch=thunk # -mfunction-return=thunk

LDLIBS += -lrt -lpthread
OBJS = sample.o retpoline.o
EXTRA_OBJS = foo.o
OBJS += latency.o
OBJS += test_timers.o
PROGS = $(OBJS:.o=)

all: $(PROGS)

%:      ../ustats.o %.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

retpoline : foo.o
retpoline.o : lfsr.h

$(OBJS): ../ustats.h Makefile

clean:
	rm $(OBJS) $(EXTRA_OBJS) $(PROGS)
