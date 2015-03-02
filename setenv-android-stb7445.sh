##
# You need to modify the exports below for your platform.
##

###################################################################
# setting the path for cross compiler
###################################################################
export LINUXVER=3.8.2
export KERNELDIR=/projects/hnd_video5/kernels/3.8-2.1/7445b0-android
export CROSSTOOL=/projects/hnd_video5/kernels/3.8-2.1/stbgcc-4.5.4-2.5/bin
export PATH=${CROSSTOOL}:$PATH
export LINUXDIR=${KERNELDIR}/linux
export ROOTDIR=${KERNELDIR}/uclinux-rootfs
#export EXTERNAL_OPENSSL=0
#export EXTERNAL_OPENSSL_BASE=${KERNELDIR}/openssl
export LIBUSB_PATH=${ROOTDIR}/lib/libusb
export TARGETDIR=${LINUXVER}

###################################################################
# USBSHIM=1 if kernel is greater than or equal to 2.6.18
# USBSHIM=0 if kernel is less than 2.6.18 or using DBUS kernel object.
###################################################################
export USBSHIM=0

###################################################################
# Machine and Architecture specifics
###################################################################
export TARGETMACH=armle
export TARGETARCH=arm
export TARGETENV=linuxarm
export CC=arm-linux-gcc
export STRIP=arm-linux-strip
export CROSS_COMPILE=arm-linux-	


###################################################################
# DO NOT MODIFY BELOW THIS LINE
###################################################################
source ./setenv.sh

