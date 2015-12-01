##
# You need to modify the exports below for your platform.
##

###################################################################
# setting the path for cross compiler
###################################################################
export LINUXVER=3.1.10
export KERNELDIR=/home/yf/linux/3.1.10
export CROSSTOOL=/opt/arm-2012.09/bin
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
export TARGETMACH=arm_le
export TARGETARCH=arm_le
export TARGETENV=linuxarm_le
export CC=arm-none-linux-gnueabi-gcc
export STRIP=arm-none-linux-gnueabi-strip
export CROSS_COMPILE=arm-none-linux-gnueabi-
#export HOST=arm-hisiv400nptl-linux

###################################################################
# DO NOT MODIFY BELOW THIS LINE
###################################################################
source ./setenv.sh
source ./setenv-for-libnl-openssl.sh
