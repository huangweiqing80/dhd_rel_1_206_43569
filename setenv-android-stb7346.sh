##
# You need to modify the exports below for your platform.
##

###################################################################
# setting the path for cross compiler
###################################################################
export LINUXVER=3.3.6
export KERNELDIR=/projects/hnd_video4/kernels/3.3-1.1/7346b0-android
export CROSSTOOL=/projects/hnd_video4/kernels/3.3-1.1/stbgcc-4.5.3-2.3/bin
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
# TARGETMACH=mipseb is BE
# TARGETMACH=mipsel is LE
###################################################################
export TARGETMACH=mipsel
export TARGETARCH=mips
export TARGETENV=linuxmips
export CC=mipsel-linux-gcc
export STRIP=mipsel-linux-strip
export CROSS_COMPILE=mipsel-linux-	


###################################################################
# DO NOT MODIFY BELOW THIS LINE
###################################################################
source ./setenv.sh

