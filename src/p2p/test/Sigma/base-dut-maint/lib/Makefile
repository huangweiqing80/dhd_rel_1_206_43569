include ../Makefile.inc

ifneq ($(origin extsec),undefined)
CFLAGS += -DBRCM_P2P_EXTSEC
endif

all:    ${LIB_OBJS}
		${AR} crv $(OBJDIR)/${LIBWFA_NAME} $?
		${AR} crv $(OBJDIR)/${LIBWFA_NAME_DUT} $?
		${AR} crv $(OBJDIR)/${LIBWFA_NAME_CA} ${LIB_OBJS_CA}
#		ar crv $(OBJDIR)/${LIBWFA_NAME_CA} $?
#		${RANLIB} $(OBJDIR)/${LIBWFA_NAME} $(OBJDIR)/${LIBWFA_NAME_DUT} $(OBJDIR)/${LIBWFA_NAME_CA}

# Treat warnings as errors.
# -U_FORTIFY_SOURCE is required for ignoring the return value of system call. Ubuntu build gives error if return value of system() is not used
$(OBJDIR)/wfa_cs.o: CFLAGS += -Werror -U_FORTIFY_SOURCE
wfa_tg.o: wfa_tg.c ../inc/wfa_agt.h ../inc/wfa_types.h ../inc/wfa_rsp.h ../inc/wfa_tlv.h  ../inc/wfa_tg.h

wfa_cs.o: wfa_cs.c ../inc/wfa_agt.h ../inc/wfa_types.h ../inc/wfa_rsp.h ../inc/wfa_tlv.h

wfa_ca_resp.o: wfa_ca_resp.c ../inc/wfa_agtctrl.h ../inc/wfa_types.h ../inc/wfa_rsp.h ../inc/wfa_tlv.h ../inc/wfa_types.h

wfa_cmdproc.o: wfa_cmdproc.c ../inc/wfa_agtctrl.h ../inc/wfa_types.h ../inc/wfa_tg.h ../inc/wfa_tlv.h

wfa_cmdtbl.o: wfa_cmdtbl.c ../inc/wfa_types.h ../inc/wfa_tlv.h

wfa_sock.o: wfa_sock.c ../inc/wfa_sock.h ../inc/wfa_types.h

wfa_thr.o: wfa_thr.c ../inc/wfa_tg.h 

wfa_wmmps.o: wfa_wmmps.c ../inc/wfa_wmmps.h

clean:
		rm -Rf ${PROGS} ${CLEANFILES}
