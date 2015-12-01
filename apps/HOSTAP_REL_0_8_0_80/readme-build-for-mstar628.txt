Sample build steps ( for linux 3.10.y on Hisi3536)
1.	source setenv-arm-hi3536.sh (Set Cross Compiler Environment)

2.	cd OPENSSL/openssl-1.0.1g
./Configure linux-armv4
make CC=arm-none-linux-gnueabi-gcc

3.	cd libnl-3.2.14
./configure --host=arm-none-linux
make CC=arm-none-linux-gnueabi-gcc clean
make CC=arm-none-linux-gnueabi-gcc
cp lib/.libs/libnl-3.a ./libnl.a
cp lib/.libs/libnl-genl-3.a ./libnl-genl.a

4.	cd libbcmdhd
make CC=arm-none-linux-gnueabi-gcc clean
make CC=arm-none-linux-gnueabi-gcc

5.	cd wpa_supplicant
make CC=arm-none-linux-gnueabi-gcc clean
make CC=arm-none-linux-gnueabi-gcc
