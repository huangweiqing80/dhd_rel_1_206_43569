# Makefile for test program driver 
# RTT 2009-09-30
#

SRCBASE = ../../
include $(SRCBASE)/Makerules


OBJS = cli.o
CFLAGS += -I$(SRCBASE)/include -I$(SRCBASE)/common/include -I../include



stuff: $(OBJS)
	echo "done"
#$(CC) -o stuff $(OBJS)

	


clean: $(lib-clean)
	rm -f *.o *.d *.a stuff


%.o:	%.c
	$(CC) -c $(CFLAGS) -o $@ $<

.PHONY: dummy
