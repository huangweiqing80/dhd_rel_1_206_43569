##
# You need to modify the exports below for your platform.
##

###################################################################
# setting the path for cross compiler
###################################################################
export LINUXVER=3.10.0
export KERNELDIR=/home/yf/linux/linux-3.10.y
export CROSSTOOL=/opt/hisi-linux/x86-arm/arm-hisiv400-linux/bin
export PATH=${CROSSTOOL}:$PATH
export LINUXDIR=${KERNELDIR}
# export ROOTDIR=${KERNELDIR}/uclinux-rootfs
#export EXTERNAL_OPENSSL=0
#export EXTERNAL_OPENSSL_BASE=${KERNELDIR}/openssl
export LIBUSB_PATH=${ROOTDIR}/lib/libusb
export TARGETDIR=${LINUXVER}

###################################################################
# USBSHIM=1 if kernel is greater than or equal to 2.6.18
# USBSHIM=0 if kernel is less than 2.6.18 or using DBUS kernel object.
###################################################################
export USBSHIM=1

###################################################################
# Machine and Architecture specifics
# TARGETMACH=arm is BE
# TARGETMACH=arm_le is LE
###################################################################
export ARCH=arm
export TARGETMACH=armle
export TARGETARCH=arm
export TARGETENV=linuxarm
export CC=arm-hisiv400-linux-gnueabi-gcc
export STRIP=arm-hisiv400-linux-gnueabi-strip
export CROSS_COMPILE=arm-hisiv400-linux-gnueabi-



###################################################################
# DO NOT MODIFY BELOW THIS LINE
###################################################################
source ./setenv.sh

