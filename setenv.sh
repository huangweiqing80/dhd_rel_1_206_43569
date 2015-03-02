##
# You need to modify the exports below for your platform.
##

if [ "$1" == 4323 ] ; then
	export CHIPVER=4322
	echo "using ${CHIPVER}"
elif [ "$1" == 4360b ] ; then
	export CHIPVER=4360b
	echo "using ${CHIPVER}"
elif [ "$1" == 43143b0 ] ; then
	export CHIPVER=43143b0
	echo "using ${CHIPVER}"
elif [ "$1" == 43236b ] ; then
	export CHIPVER=43236b
	echo "using ${CHIPVER}"
elif [ "$1" == 43238b ] ; then
	export CHIPVER=43238b
	echo "using ${CHIPVER}"
elif [ "$1" == 43242a0 ] ; then
	export CHIPVER=43242a0
	echo "using ${CHIPVER}"
elif [ "$1" == 43242a1 ] ; then
	export CHIPVER=43242a1
	echo "using ${CHIPVER}"
elif [ "$1" == 43526a ] ; then
	export CHIPVER=43526a
	echo "using ${CHIPVER}"
elif [ "$1" == 43526b ] ; then
	export CHIPVER=43526b
	echo "using ${CHIPVER}"
elif [ "$1" == 43569a0 ] ; then
	export CHIPVER=43569a0
	echo "using ${CHIPVER}"
elif [ "$1" == 43570a0 ] ; then
	export CHIPVER=43570a0
	echo "using ${CHIPVER}"
else
	echo ""
	echo "==========================================="
	echo "Usage:"
	echo "source setenv-xxx.sh 4323"
	echo "source setenv-xxx.sh 4360b"	
	echo "source setenv-xxx.sh 43143b0"
	echo "source setenv-xxx.sh 43236b"	
	echo "source setenv-xxx.sh 43238b"
	echo "source setenv-xxx.sh 43242a0"	
	echo "source setenv-xxx.sh 43242a1"	
	echo "source setenv-xxx.sh 43526a"	
	echo "source setenv-xxx.sh 43526b"	
	echo "source setenv-xxx.sh 43569a0"	
	echo "source setenv-xxx.sh 43570a0"	
	echo "source setenv-xxx.sh <chipver>"		
	echo "==========================================="
	echo ""
	export CHIPVER=$1
	echo "Setting default CHIPVER to ${CHIPVER}"
	echo ""
fi

