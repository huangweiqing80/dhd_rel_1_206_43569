include ../Makefile.inc
BINDIR := $(OBJDIR)

PROGS = $(BINDIR)/wfa_scripts 

all: ${PROGS}
$(BINDIR)/wfa_scripts: $(OBJDIR)/wfa_scripts.o
	@mkdir -pv $(@D)
	${CC} ${CFLAGS} -DDEBUG=1 -o $@ $(OBJDIR)/wfa_scripts.o

clean:
	rm -Rf ${PROGS} ${CLEANFILES}
