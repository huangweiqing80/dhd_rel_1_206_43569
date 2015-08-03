##
# You need to modify the exports below for your platform.
##

###################################################################
# setting the path for cross compiler
###################################################################
export LINUXVER=3.10.33
export KERNELDIR=/home/yf/amlogic/openlinux_kk-amlogic/out/target/product/n200/obj/KERNEL_OBJ
export CROSSTOOL=/opt/hisi-linux/x86-arm/arm-hisiv200-linux/bin
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
# export CC=arm-none-linux-gnueabi-gcc
# export STRIP=arm-none-linux-gnueabi-strip
# export CROSS_COMPILE=arm-none-linux-gnueabi-	
export CC=arm-hisiv200-linux-gnueabi-gcc
export STRIP=arm-hisiv200-linux-gnueabi-strip
export CROSS_COMPILE=arm-hisiv200-linux-gnueabi-	


###################################################################
# DO NOT MODIFY BELOW THIS LINE
###################################################################
source ./setenv.sh

