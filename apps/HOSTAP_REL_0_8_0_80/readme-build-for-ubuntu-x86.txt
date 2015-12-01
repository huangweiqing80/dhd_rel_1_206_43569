Sample build steps ( for Android linux 3.3.6 on STB)
1.	

2.	cd OPENSSL/openssl-1.0.1g
./Configure linux-x86_64
make

3.	cd libnl-3.2.14
./configure
make clean
make
cp lib/.libs/libnl-3.a ./libnl.a
cp lib/.libs/libnl-genl-3.a ./libnl-genl.a

4.	cd libbcmdhd
make CC=arm-hisiv400-linux-gnueabi-gcc clean
make CC=arm-hisiv400-linux-gnueabi-gcc

5.	cd wpa_supplicant
make CC=arm-hisiv400-linux-gnueabi-gcc clean
make CC=arm-hisiv400-linux-gnueabi-gcc
