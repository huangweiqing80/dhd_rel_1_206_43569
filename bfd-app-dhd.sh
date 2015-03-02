#!/bin/bash

mkdir ${TARGETDIR}

make -C src/dhd/exe CC=${CC} STRIP=${STRIP} $1

if [ ${TARGETARCH} == x86 ] ; then
	cp -v src/dhd/exe/dhd ${TARGETDIR}/dhd
	cp -v src/dhd/exe/dhd ${TARGETDIR}/dhd-x86
elif [ ${TARGETARCH} == mips ] ; then
	cp -v src/dhd/exe/dhdmips ${TARGETDIR}/dhd
	cp -v src/dhd/exe/dhdmips ${TARGETDIR}/dhd-${TARGETMACH}
elif [ ${TARGETARCH} == arm ] ; then
	cp -v src/dhd/exe/dhdarm ${TARGETDIR}/dhd
	cp -v src/dhd/exe/dhdarm ${TARGETDIR}/dhd-${TARGETMACH}
else
	echo "UNKNOWN TARGETARCH == ${TARGETARCH}"
fi
