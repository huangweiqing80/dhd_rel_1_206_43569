include ../Makefile.inc

PROGS = $(BINDIR)/ca_cli
#PROGS = $(OBJDIR)/ca_cli $(OBJDIR)/tc_cli 

all: ${PROGS}

$(BINDIR)/ca_cli: $(OBJDIR)/ca_cli.o ../lib/$(OBJDIR)/wfa_miscs.o ../lib/$(OBJDIR)/wfa_sock.o
	@mkdir -pv $(@D)
	${CC} ${CFLAGS} -o $@ $(OBJDIR)/ca_cli.o ../lib/$(OBJDIR)/wfa_miscs.o ../lib/$(OBJDIR)/wfa_sock.o
#	${CC} ${CFLAGS} -o $@ $(OBJDIR)/ca_cli.o ${DUTLIBS}

#$(OBJDIR)/tc_cli: $(OBJDIR)/tc_cli.o
#	${CC} ${CFLAGS} -o $@ $(OBJDIR)/tc_cli.o ${DUTLIBS}

clean:
	rm -Rf ${PROGS} ${CLEANFILES}
