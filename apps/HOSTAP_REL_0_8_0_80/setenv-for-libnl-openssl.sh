SETENV_PATH=`pwd`
SRC_PATH=.
LIBNL_SRC=libnl-3.2.14
LIBNL_PREFIX=`pwd`/$LIBNL_SRC/target
#LIBNL_CONFIGED_FILE="libnl-1.pc Makefile.opts config.log config.status"
#LIBNL_CONFIGED_LIB="doc lib"
OPENSSL_SRC_PATH=./OPENSSL
OPENSSL_SRC=openssl-1.0.1g
OPESSL_PREFIX=`pwd`/OPENSSL/$OPENSSL_SRC/target

function config_libnl()
{
	if [ $# -lt 1 ];then
		echo "please write the libnl name for the shell"
		return 1
	elif [ $# -gt 1 ];then
		echo "too many argument"
		return 1
	else
		if [ -d $SRC_PATH/$1 ];then
			echo "file already exit"
			#rm -rvf $SRC_PATH/$1
		else
		tar -xvf $SRC_PATH/$1.tar.gz -C $SRC_PATH
		fi
	fi

	#if [ -f $MAKEFILE_DIR/$LIBNL_MAKEFILE ];then
		#cp -v $SRC_PATH/$1/Makefile $SRC_PATH/$1/Makefile.bak
	    #cp -v $MAKEFILE_DIR/$LIBNL_MAKEFILE $SRC_PATH/$1/Makefile
	#else
		#echo "`echo $1`:not found the new Makefile ,use the original!!!!!! "
	#fi
	cd $SRC_PATH/$1
	./configure --host=$HOST --prefix=$LIBNL_PREFIX
	#mv -v $LIBNL_CONFIGED_FILE $SRC_PATH/$1
	#cp -rvf $LIBNL_CONFIGED_LIB $SRC_PATH/$1
	#rm -rvf $LIBNL_CONFIGED_LIB
	#make -C $SRC_PATH/$1
	#make -C $SRC_PATH/$1 install&&\
	#cp -v $SRC_PATH/$1/target/lib/libnl.so* $OUT_DIR
	cd $SETENV_PATH
}

function config_openssl()
{
	if [ $# -lt 1 ];then
		echo "please write the openssl name for the OPENSSL_SRC"
		return 1
	elif [ $# -gt 2 ];then
		echo "too many openssl argument"
		return 1
	else
		if [ -d $OPENSSL_SRC_PATH/$1 ];then
			echo "file already exit"
			#rm -rvf $SRC_PATH/$1
		else
		tar -xvf $OPENSSL_SRC_PATH/$1.tar.gz -C $OPENSSL_SRC_PATH
		fi
	fi
	cd $OPENSSL_SRC_PATH/$1
	./Configure linux-armv4 --cross-compile-prefix=$CROSS_COMPILE --openssldir=$OPESSL_PREFIX
	cd $SETENV_PATH
	
	
}



config_libnl $LIBNL_SRC
config_openssl $OPENSSL_SRC
