include ../Makefile.inc

PROGS = $(BINDIR)/wfa_ca 

all: ${PROGS}

$(BINDIR)/wfa_ca: $(OBJDIR)/wfa_ca.o ${CALIBS}
	@mkdir -pv $(@D)
	${CC} ${CFLAGS} -DDEBUG=1 -o $@ $(OBJDIR)/wfa_ca.o ${CALIBS}

clean:
	rm -Rf ${PROGS} ${CLEANFILES}
