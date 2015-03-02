##
# You need to modify the exports below for your platform.
##

###################################################################
# setting the path for cross compiler
###################################################################
export LINUXVER=2.6.37
export KERNELDIR=/projects/hnd_video4/kernels/2.6.37-3.0/7346b0
export CROSSTOOL=/projects/hnd_video4/kernels/2.6.37-3.0/stbgcc-4.5.3-2.1/bin
export PATH=${CROSSTOOL}:$PATH
export LINUXDIR=${KERNELDIR}/stblinux-${LINUXVER}
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
# TARGETMACH=arm is BE
# TARGETMACH=arm_le is LE
###################################################################
export TARGETMACH=arm
export TARGETARCH=arm
export TARGETENV=linuxarm
export CC=arm-linux-gnueabi-gcc
export STRIP=arm-linux-gnueabi-strip
export CROSS_COMPILE=arm-linux-gnueabi-


###################################################################
# DO NOT MODIFY BELOW THIS LINE
###################################################################
source ./setenv.sh

