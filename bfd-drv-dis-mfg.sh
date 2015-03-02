#!/bin/bash


if [ "${TARGETARCH}" == x86 ] ; then
	if [ "${CHIPVER}" == 43570a0 ] ; then
		export BUILDCFG=dhd-msgbuf-pciefd
		export STBLINUX=0
	else
		export BUILDCFG=dhd-cdc-usb-gpl
		export STBLINUX=0
	fi
elif [ "${TARGETARCH}" == mips ] ; then
	if [ "${TARGETMACH}" == mipseb ] ; then 
		export BUILDCFG=dhd-cdc-usb-gpl-be
		export STBLINUX=1
		export CROSS_COMPILE=mips-linux-	
	elif [ "${TARGETMACH}" == mipsel ] ; then
		export BUILDCFG=dhd-cdc-usb-gpl
		export STBLINUX=1
		export CROSS_COMPILE=mipsel-linux-	
	else
		echo "TARGETARCH==${TARGETARCH}"
		echo "TARGETMACH==${TARGETMACH} undefined"
		exit
	fi
elif [ "${TARGETARCH}" == arm ] ; then
	if [ "${TARGETMACH}" == armeb ] ; then 
		export BUILDCFG=dhd-cdc-usb-gpl-be
		export STBLINUX=1
		export CROSS_COMPILE=arm-linux-	
	elif [ "${TARGETMACH}" == armle ] ; then
		export BUILDCFG=dhd-cdc-usb-gpl
		export STBLINUX=1
		export CROSS_COMPILE=arm-linux-	
	else
		echo "TARGETARCH==${TARGETARCH}"
		echo "TARGETMACH==${TARGETMACH} undefined"
		exit
	fi
else
	echo "TARGETARCH==${TARGETARCH} undefined"
	exit
fi




export WLTEST=1
export DNGL_IMAGE_NAME="NOT NEEDED"

if [ "$1" == clean ] ; then
	rm -vrf ./src/dhd/linux/dhd-*
	exit
else
	export BUILDARG="$1"
fi


echo ""
echo "************************************************"
echo "      DNGL_IMAGE_NAME = ${DNGL_IMAGE_NAME}      "
echo "      BUILDCFG   = "${BUILDCFG}"                "
echo "      BUILDARG   = "${BUILDARG}"                "
echo "************************************************"
echo ""
sleep 3

if [ ! -d ${TARGETDIR} ]; then
mkdir ${TARGETDIR}
fi

if [ ! -d ./src/dhd/linux/${BUILDCFG}-${LINUXVER} ]; then
mkdir ./src/dhd/linux/${BUILDCFG}-${LINUXVER}
fi

if [ ! -f ./src/include/epivers.h ]; then
cd ./src/include
make
cd -
fi


make -C ./src/dhd/linux ${BUILDCFG} WLTEST=${WLTEST} WLLXIW=${WLLXIW} LINUXVER=${LINUXVER} ${BUILDARG} CC=${CC} STRIP=${STRIP} V=1

if [ -f ./src/dhd/linux/${BUILDCFG}-${LINUXVER}/dhd.ko ]; then
cp  -v ./src/dhd/linux/${BUILDCFG}-${LINUXVER}/dhd.ko ${TARGETDIR}
cp  -v ./src/dhd/linux/${BUILDCFG}-${LINUXVER}/dhd.ko ${TARGETDIR}/${BUILDCFG}-dhd.ko
fi

if [ -f ./src/dhd/linux/${BUILDCFG}-${LINUXVER}/bcmdhd.ko ]; then
cp  -v ./src/dhd/linux/${BUILDCFG}-${LINUXVER}/bcmdhd.ko ${TARGETDIR}
cp  -v ./src/dhd/linux/${BUILDCFG}-${LINUXVER}/bcmdhd.ko ${TARGETDIR}/${BUILDCFG}-bcmdhd.ko
fi

