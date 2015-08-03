#!/bin/bash

CUR_DIR=`pwd`
export LIBUSB=${CUR_DIR}/src/usbdev/libusb-1.0.9
export LIBUSB_COMPACT=${CUR_DIR}/src/usbdev/libusb-compat-0.1.3
if [ "${TARGETDIR}"="" ]; then
export TARGETDIR=`uname -r`
mkdir ${TARGETDIR}
else
mkdir ${TARGETDIR}
fi
cd ${CUR_DIR}/src/usbdev
tar xvf libusb-1.0.9.tar.bz2
tar xvf libusb-compat-0.1.3.tar.bz2
cd ${LIBUSB}
./configure
make
make install
cd ${LIBUSB_COMPACT}
./configure
make
make install
cd ${CUR_DIR}
make -C src/usbdev/usbdl
rm -rf ${LIBUSB}
rm -rf ${LIBUSB_COMPACT}
if [ "${TARGETARCH}" == mips ] ; then
	cp -v src/usbdev/usbdl/mips/bcmdl ${TARGETDIR}
	cp -v src/usbdev/usbdl/mips/bcmdl ${TARGETDIR}/bcmdl-${TARGETMACH}
else
	cp -v src/usbdev/usbdl/bcmdl ${TARGETDIR}
	cp -v src/usbdev/usbdl/bcmdl ${TARGETDIR}/bcmdl-${TARGETMACH}
fi
