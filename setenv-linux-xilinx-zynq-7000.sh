## 
# You need to modify the exports below for your platform.
##

###################################################################
# setting the path for cross compiler
###################################################################
export LINUXVER=3.19.0
#export LINUXVER=
#export KERNELDIR=/usr/src/linux-3.3.8
#export KERNELDIR=/home/iton1/Iton/work/xilinx/Zynq-7000/materials/linux-xlnx-xilinx-v2015.2.01
export KERNELDIR=/home/hwd/linux/xilinx/linux-xlnx-xilinx-v2015.2.01
export CROSSTOOL=/opt/lin/bin
#export PATH=${CROSSTOOL}:$PATH
#export LINUXDIR=${KERNELDIR}/stblinux-${LINUXVER}
export LINUXDIR=${KERNELDIR}
#export ROOTDIR=${KERNELDIR}/uclinux-rootfs
#export EXTERNAL_OPENSSL=0
#export EXTERNAL_OPENSSL_BASE=${KERNELDIR}/openssl
#export LIBUSB_PATH=`pwd`/usbdev/install/lib
export TARGETDIR=${LINUXVER}
#export COMPAT_WIRELESS = /home/hwd/linux/patch/backports-3.14-1

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
export TARGETMACH=armle
export TARGETARCH=arm
export TARGETENV=linuxarm_le
#export CC=arm-linux-gnueabi-gcc
#export STRIP=arm-linux-gnueabi-strip
#export CROSS_COMPILE=arm-linux-gnueabi-
export CC=arm-xilinx-linux-gnueabi-gcc
export STRIP=arm-xilinx-linux-gnueabi-strip
export CROSS_COMPILE=arm-xilinx-linux-gnueabi-
#add by hwd
export ARCH=arm
export PLATFORM=XILINX_ZYNQ_7000
export PATH=$CROSSTOOL:$PATH
###################################################################
# DO NOT MODIFY BELOW THIS LINE
###################################################################
source ./setenv.sh

