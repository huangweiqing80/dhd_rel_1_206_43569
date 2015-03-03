#!/bin/bash

CUR_DIR=`pwd`
export LIBUSB=${CUR_DIR}/src/usbdev/libusb-1.0.9
export LIBUSB_COMPACT=${CUR_DIR}/src/usbdev/libusb-compat-0.1.3
mkdir ${TARGETDIR}
cd ${LIBUSB}
./configure --prefix=`pwd`/install --host=arm-linux CC=arm-hisiv200-linux-gnueabi-gcc
make
make install
cd ${LIBUSB_COMPACT}
./configure --prefix=`pwd`/install LIBUSB_1_0_CFLAGS=-isystem${LIBUSB}/install/include/libusb-1.0 LIBUSB_1_0_LIBS=-L${LIBUSB}/install/lib --host=arm-linux
make
make install
cd ${CUR_DIR}
make -C src/usbdev/usbdl CC=${CC} STRIP=${STRIP} LIBUSB_PATH=${LIBUSB} LIBUSB_COMPACT_PATH=${LIBUSB_COMPACT} $1

if [ "${TARGETARCH}" == mips ] ; then
	cp -v src/usbdev/usbdl/mips/bcmdl ${TARGETDIR}
	cp -v src/usbdev/usbdl/mips/bcmdl ${TARGETDIR}/bcmdl-${TARGETMACH}
else
	cp -v src/usbdev/usbdl/bcmdl ${TARGETDIR}
	cp -v src/usbdev/usbdl/bcmdl ${TARGETDIR}/bcmdl-${TARGETMACH}
fi
