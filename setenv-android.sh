##
# You need to modify the exports below for your platform.
##

###################################################################
# setting the path for cross compiler
###################################################################
export LINUXVER=4.4.16
export KERNELDIR=/data/msl/work/Android/Rockchip/X3399/x3399_marshmallow/kernel
export CROSSTOOL=/data/msl/work/Android/Rockchip/X3399/x3399_marshmallow/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin
export PATH=${CROSSTOOL}:$PATH
export LINUXDIR=${KERNELDIR}
export ROOTDIR=${KERNELDIR}/uclinux-rootfs
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
# TARGETMACH=mipseb is BE
# TARGETMACH=mipsel is LE
###################################################################
export ARCH=arm
export TARGETMACH=armle
export TARGETARCH=arm
export TARGETENV=linuxarm
export CC=aarch64-linux-android-gcc
export STRIP=arm-none-linux-gnueabi-strip
export CROSS_COMPILE=/data/msl/work/Android/Rockchip/X3399/x3399_marshmallow/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin/arm-none-linux-gnueabi-	


###################################################################
# DO NOT MODIFY BELOW THIS LINE
###################################################################
source ./setenv.sh

