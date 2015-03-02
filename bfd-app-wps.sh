#!/bin/bash

mkdir ${TARGETDIR}

cd src/wps/common/include/
make
cd -

cd src/wps/linux/enr/
make -f wps_enr_app.mk CC=${CC} STRIP=${STRIP} EXTERNAL_OPENSSL=${EXTERNAL_OPENSSL} V=1 BCM_WPS_IOTYPECOMPAT=1 $1
cd -

cp -v src/wps/linux/enr/${CC}/wpsenr ${TARGETDIR}
cp -v src/wps/linux/enr/${CC}/wpsenr ${TARGETDIR}/wpsenr-${TARGETMACH}

cp -v src/wps/linux/enr/${CC}/wpsreg ${TARGETDIR}
cp -v src/wps/linux/enr/${CC}/wpsreg ${TARGETDIR}/wpsreg-${TARGETMACH}

