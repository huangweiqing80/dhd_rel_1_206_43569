#!/bin/bash

if [ "${CHIPVER}" == 43236b ] || [ "${CHIPVER}" == 43238b ] ; then
	export BUILDCFG_COMMON=dhd-cdc-usb-android-stb-jellybean-cfg80211-noproptxstatus
elif [ "${CHIPVER}" == 43242a1 ] ; then
	export BUILDCFG_COMMON=dhd-cdc-usb-android-stb-jellybean-cfg80211-comp
elif [ "${CHIPVER}" == 43569a0 ] ; then
	export BUILDCFG_COMMON=dhd-cdc-usb-android-stb-jellybean-cfg80211-comp-mfp
elif [ "${CHIPVER}" == 43570a0 ] ; then
	export BUILDCFG_COMMON=dhd-msgbuf-pciefd-android-stb-jellybean-cfg80211-mfp
else
	export BUILDCFG_COMMON=dhd-cdc-usb-android-stb-jellybean-cfg80211
fi

if [ "${TARGETARCH}" == x86 ] ; then
	export BUILDCFG=${BUILDCFG_COMMON}
	export STBLINUX=0
elif [ "${TARGETARCH}" == mips ] ; then
	if [ "${TARGETMACH}" == mipseb ] ; then 
		export BUILDCFG=${BUILDCFG_COMMON}-be
		export STBLINUX=1
		export CROSS_COMPILE=mips-linux-	
	elif [ "${TARGETMACH}" == mipsel ] ; then
		export BUILDCFG=${BUILDCFG_COMMON}
		export STBLINUX=1
		export CROSS_COMPILE=mipsel-linux-	
	else
		echo "TARGETARCH==${TARGETARCH}"
		echo "TARGETMACH==${TARGETMACH} undefined"
		exit
	fi
elif [ "${TARGETARCH}" == arm ] ; then
	if [ "${TARGETMACH}" == armeb ] ; then 
		export BUILDCFG=${BUILDCFG_COMMON}-be
		export STBLINUX=1
		export CROSS_COMPILE=arm-linux-	
	elif [ "${TARGETMACH}" == armle ] ; then
		export BUILDCFG=${BUILDCFG_COMMON}
		export STBLINUX=1
		#export CROSS_COMPILE=arm-linux-	
	else
		echo "TARGETARCH==${TARGETARCH}"
		echo "TARGETMACH==${TARGETMACH} undefined"
		exit
	fi
else
	echo "TARGETARCH==${TARGETARCH} undefined"
	exit
fi

export WLTEST=0
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
echo "      BUILDCFG = "${BUILDCFG}"                  "
echo "      BUILDARG = "${BUILDARG}"                  "
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

