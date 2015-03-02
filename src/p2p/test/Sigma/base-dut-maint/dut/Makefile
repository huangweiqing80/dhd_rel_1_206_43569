
include ../Makefile.inc

PROGS = $(BINDIR)/wfa_dut $(OBJDIR)/wfa_dut_init.o


BRCM_P2P_DUTLIBS := ${BRCM_P2P_DIR}/linux/sampleapp/${BRCM_P2P_OBJDIR}/libbcmp2papp.a \
	${BRCM_P2P_DIR}/linux/${BRCM_P2P_OBJDIR}/libbcmp2p.a \
                    ${BRCM_P2P_DIR}/linux/${BRCM_P2P_OBJDIR}/libbcmp2psig.a \
                    ${BRCM_WPS_DIR}/wpscli/linux/${BRCM_OBJDIR}/libwpscli.a \
                    ${BRCM_WPS_DIR}/wpscli/linux/${BRCM_OBJDIR}/libwpscliosl.a \
                    ${BRCM_WPS_DIR}/wpscli/linux/${BRCM_OBJDIR}/libwpscore.a \
                    ${BRCM_WPS_DIR}/wpscli/linux/${BRCM_OBJDIR}/libbcmcrypto.a \
                    ${BRCM_P2P_DIR}/linux/${BRCM_OBJDIR}/libdhcpd.a \
                    ${BRCM_WFDCAPD_DIR}/linux/wfd_capd_ie/${BRCM_OBJDIR}/libwfdcapdie.a


# Link real-time library by default.
ifeq ($(LINK_REALTIME_LIB),)
   LINK_REALTIME_LIB := 1
endif

ifeq ($(LINK_REALTIME_LIB),1)
   BRCM_P2P_DUTLIBS += -lrt
endif

ifneq ($(origin extsec),undefined)
BRCM_P2P_DUTLIBS += ${BRCM_SECFRW_DIR}/${BRCM_P2P_OBJDIR}/libhslbcmsec.a
endif


all: ${PROGS}

$(OBJDIR)/wfa_dut_init.o : wfa_dut_init.c

$(BINDIR)/wfa_dut: $(OBJDIR)/wfa_dut.o $(OBJDIR)/wfa_dut_init.o ../lib/$(OBJDIR)/libwfa_dut.a
	# make sure the libraries are up-to-date
	make -C ${BRCM_P2P_DIR}/linux/sampleapp libs
	@mkdir -pv $(@D)
	${CC} ${CFLAGS} -o $@ $(OBJDIR)/wfa_dut.o $(OBJDIR)/wfa_dut_init.o ${DUTLIBS} ${BRCM_P2P_DUTLIBS}

clean:
	rm -Rf ${PROGS} ${CLEANFILES}
