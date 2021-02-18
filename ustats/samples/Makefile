# Some sample programs for ustats
CFLAGS += -Wall -Werror -O3 -g -static -I ..

# clang flags for retpoline
CC=clang
CFLAGS += -mretpoline-external-thunk

# gcc flags for retpoline
# choices are keep, thunk, think-extern
#CC=gcc
#CFLAGS += -mindirect-branch=thunk # -mfunction-return=thunk

LDLIBS += -lrt -lpthread
OBJS = sample.o retpoline.o foo.o
PROGS = sample retpoline

all: $(PROGS)

sample: ../ustats.o sample.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

retpoline: ../ustats.o retpoline.o foo.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
retpoline.o : lfsr.h

$(OBJS): ../ustats.h Makefile

clean:
	rm $(OBJS) $(PROGS)
