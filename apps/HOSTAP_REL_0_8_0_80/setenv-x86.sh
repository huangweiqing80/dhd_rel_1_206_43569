##
# You need to modify the exports below for your platform.
##

###################################################################
# setting the path for cross compiler
###################################################################
export LINUXVER=`uname -r`
export KERNELDIR=
export CROSSTOOL=
export CROSS_COMPILE=
#export PATH=${CROSSTOOL}:$PATH
export LINUXDIR=/lib/modules/${LINUXVER}/build
export ROOTDIR=
export EXTERNAL_OPENSSL=0
export EXTERNAL_OPENSSL_BASE=
export LIBUSB_PATH=
export TARGETDIR=${LINUXVER}

###################################################################
# USBSHIM=1 if kernel is greater than or equal to 2.6.18
# USBSHIM=0 if kernel is less than 2.6.18 or using DBUS kernel object.
###################################################################
export USBSHIM=0

###################################################################
# Machine and Architecture specifics
# TARGETMACH=x86 is BE
# TARGETMACH=x86 is LE
###################################################################
export TARGETMACH=
export TARGETARCH=x86
export TARGETENV=linux
export CC=gcc
export STRIP=strip


###################################################################
# DO NOT MODIFY BELOW THIS LINE
###################################################################
source ./setenv.sh

