
BUILDDIR=`pwd`

cd OPENSSL/openssl-1.0.1g
#./Configure linux-armv4
make CC=${CC}
cd ${BUILDDIR}

cd libnl-3.2.14
#./configure --host=${HOST}
#make CC=${CC} clean
make CC=${CC}
cp lib/.libs/libnl-3.a ./libnl.a
cp lib/.libs/libnl-genl-3.a ./libnl-genl.a
cd ${BUILDDIR}

cd libbcmdhd
make CC=${CC} clean
make CC=${CC}
cd ${BUILDDIR}

cd wpa_supplicant
#make CC=${CC} clean
make CC=${CC}

if [ -d ${BUILDDIR}/out ];then
    echo "folder out exist, do not need to create it!"
else    
    mkdir ${BUILDDIR}/out
fi
${STRIP} wpa_supplicant
${STRIP} wpa_cli
cp wpa_supplicant ${BUILDDIR}/out
cp wpa_cli ${BUILDDIR}/out
cd ${BUILDDIR}

