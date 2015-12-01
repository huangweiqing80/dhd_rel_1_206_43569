##
# You need to modify the exports below for your platform.
##

###################################################################
# setting the path for cross compiler
###################################################################
export LINUXVER=3.4.y
#export KERNELDIR=/home/iton1/Iton/hi3535/Hi3535_SDK_V1.0.5.0/osdrv/kernel/linux-3.4.y
export KERNELDIR=/home/iton1/Iton/hi3535/Hi3535_SDK_V1.0.5.0/osdrv/kernel/linux-3.4.y


export CROSSTOOL=/opt/hisi-linux-nptl/arm-hisiv100-linux/target/bin
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
export USBSHIM=1

###################################################################
# Machine and Architecture specifics
# TARGETMACH=arm is BE
# TARGETMACH=arm_le is LE
###################################################################
export TARGETMACH=arm_le
export TARGETARCH=arm_le
export TARGETENV=linuxarm_le
export CC=arm-hisiv100nptl-linux-gcc
export STRIP=arm-hisiv100nptl-linux-strip
export CROSS_COMPILE=arm-hisiv100nptl-linux-
export HOST=arm-linux

###################################################################
# DO NOT MODIFY BELOW THIS LINE
###################################################################
source ./setenv.sh
source ./libnl-openssl-config.sh
