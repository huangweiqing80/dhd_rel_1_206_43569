##
# You need to modify the exports below for your platform.
##

###################################################################
# setting the path for cross compiler
###################################################################
export LINUXVER=3.1.10
export KERNELDIR=/home/customer/Eden/3.1.10_Nike_TVOS/3.1.10
export CROSSTOOL=/opt/arm-2011.03/bin
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
export TARGETMACH=armel
export TARGETARCH=arm
export TARGETENV=linuxarm
export CC=arm-none-linux-gnueabi-gcc
export STRIP=arm-none-linux-gnueabi-strip
export CROSS_COMPILE=arm-none-linux-gnueabi-	


###################################################################
# DO NOT MODIFY BELOW THIS LINE
###################################################################
source ./setenv.sh

