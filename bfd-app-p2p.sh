#!/bin/bash



mkdir ${TARGETDIR}

if [ ${TARGETARCH} == x86 ] ; then
	OBJDIR=src/p2p/p2plib/linux/sampleapp/obj/x86-debug-intsec
elif [ ${TARGETARCH} == mips ] ; then
	if [ "${TARGETMACH}" == mipseb ] ; then 
		export CROSS_COMPILE=mips-linux-	
		export BUILDCFG=mipseb-mips-
		export STBLINUX=1
		OBJDIR=src/p2p/p2plib/linux/sampleapp/obj/mips-debug-intsec
	elif [ "${TARGETMACH}" == mipsel ] ; then
		export CROSS_COMPILE=mipsel-linux-	
		export BUILDCFG=mipsel-mips-
		export STBLINUX=1
		OBJDIR=src/p2p/p2plib/linux/sampleapp/obj/mipsel-debug-intsec
	else
		echo "TARGETARCH==${TARGETARCH}"
		echo "TARGETMACH==${TARGETMACH} undefined"
		exit
	fi
elif [ "${TARGETARCH}" == arm ] ; then
	if [ "${TARGETMACH}" == armle ] ; then 
		export BUILDCFG=armle-arm-
		export STBLINUX=1
		OBJDIR=src/p2p/p2plib/linux/sampleapp/obj/arm-debug-intsec
	elif [ "${TARGETMACH}" == armeb ] ; then
		export BUILDCFG=armeb-arm-
		export STBLINUX=1
		OBJDIR=src/p2p/p2plib/linux/sampleapp/obj/arm-debug-intsec
	else
		echo "TARGETARCH==${TARGETARCH}"
		echo "TARGETMACH==${TARGETMACH} undefined"
		exit
	fi	
else
	echo "UNKNOWN TARGETARCH == ${TARGETARCH}"
fi


make -C src/p2p/p2plib/linux/sampleapp BCM_P2P_IOTYPECOMPAT=1 $1

cp -v ${OBJDIR}/bcmp2papp ${TARGETDIR}
cp -v ${OBJDIR}/bcmp2papp ${TARGETDIR}/bcmp2papp-${TARGETMACH}

