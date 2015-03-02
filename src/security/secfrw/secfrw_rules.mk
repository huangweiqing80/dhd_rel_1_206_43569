# Common rules for secfrw/*/Makefile
#
# $Id: secfrw_rules.mk,v 1.2 2010-11-30 05:49:30 $
#

all:

ifneq ($(TARGET_LIB),)
all: $(TARGET_LIB).a
endif

clean: 
	rm -rf $(OBJDIR)

# Force creation of 32-bit x86 binaries even when compiled on a x86-64 host.
ifeq ($(CC), gcc)
  CFLAGS += -m32
endif


%.o $(OBJDIR)/%.o:	%.c
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(CC) -c $(CFLAGS) -o $@ $<

$(TARGET_LIB).a $(OBJDIR)/$(TARGET_LIB).a: $(OBJS)
	$(AR) cr$(if $(V),v) $(OBJDIR)/lib$(@F) $^
	echo "done"
