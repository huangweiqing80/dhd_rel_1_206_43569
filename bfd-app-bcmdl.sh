#!/bin/bash

mkdir ${TARGETDIR}

make -C src/usbdev/usbdl CC=${CC} STRIP=${STRIP} $1

if [ "${TARGETARCH}" == mips ] ; then
	cp -v src/usbdev/usbdl/mips/bcmdl ${TARGETDIR}
	cp -v src/usbdev/usbdl/mips/bcmdl ${TARGETDIR}/bcmdl-${TARGETMACH}
else
	cp -v src/usbdev/usbdl/bcmdl ${TARGETDIR}
	cp -v src/usbdev/usbdl/bcmdl ${TARGETDIR}/bcmdl-${TARGETMACH}
fi
