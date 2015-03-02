#!/bin/bash

mkdir ${TARGETDIR}

make -C src/wl/exe ASD=0 CC=${CC} STRIP=${STRIP} $1

if [ ${TARGETARCH} == x86 ] ; then
	cp -v src/wl/exe/wl ${TARGETDIR}/wl
	cp -v src/wl/exe/wl ${TARGETDIR}/wl-x86
elif [ ${TARGETARCH} == mips ] ; then
	cp -v src/wl/exe/wlmips ${TARGETDIR}/wl
	cp -v src/wl/exe/wlmips ${TARGETDIR}/wl-${TARGETMACH}
elif [ ${TARGETARCH} == arm ] ; then
	cp -v src/wl/exe/wlarm ${TARGETDIR}/wl
	cp -v src/wl/exe/wlarm ${TARGETDIR}/wl-${TARGETMACH}
else
	echo "UNKNOWN TARGETARCH == ${TARGETARCH}"
fi
