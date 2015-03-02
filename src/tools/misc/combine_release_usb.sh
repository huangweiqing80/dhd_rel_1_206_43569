#!/bin/bash

# Script to combine firmware from one release with host/firmware from
# another release.  The motivation is to be able to build firmware for
# some chips on one branch, and use it with the host driver and firmware
# for other chips on another branch.

usage() {
    echo >&2 "Usage: $0 <brand> <fw_tag> <chip_build> <dst_tag>"
    exit 1
}

# Brand that should be handled
if [ "$1" = "" ]; then usage; fi
BRAND="$1"; shift

# Brand that should be handled
if [ "$1" = "" ]; then usage; fi
FWTAG="$1"; shift

# Chip build that should be handled
if [ "$1" = "" ]; then usage; fi
CHIP_BUILD="$1"; shift

# Tag where the firmware should be copied
DSTTAG="$1"; shift

# Directory used by the build system for Linux builds.
BUILDDIR=/projects/hnd_swbuild/build_linux
FWRELEASE=$BUILDDIR/$FWTAG

# Determine the date for the paths used in the source (firmware)
SRCPATHFORDATE=`find /projects/hnd_swbuild/build_linux/$FWTAG/$BRAND/ -maxdepth 1 -print | sort -t. -n  -k1,1 -k2,2 -k3,3 -k4,4 | tail -1`
SRCDATE=`basename $SRCPATHFORDATE`

# Determine the date for the paths used in the destination (host)
DSTPATHFORDATE=`find /projects/hnd_swbuild/build_linux/$DSTTAG/$BRAND/ -maxdepth 1 -print | sort -t. -n -k1,1 -k2,2 -k3,3 -k4,4 | tail -1`
DSTDATE=`basename $DSTPATHFORDATE`

SRCFILELIST=`find $FWRELEASE/$BRAND/*/release/bcm/firmware/$CHIP_BUILD -print`
#echo $SRCFILELIST

for f in $SRCFILELIST
do
	DSTFILE=`echo $f|sed s/$FWTAG/$DSTTAG/|sed s/$SRCDATE/$DSTDATE/`
	if [ -f $DSTFILE ]
	then
		echo "WARNING: Destination $f exists, skipping."
		continue
	fi

	echo install -Dp $f $DSTFILE
	install -Dp $f $DSTFILE
done

# Copy wl utility from firmware release into destination package.
SRCFILELIST=`find $FWRELEASE/$BRAND/*/release/bcm/apps/wl* -print`

for f in $SRCFILELIST
do
	DSTFILE=`echo $f|sed s/$FWTAG/$DSTTAG/|sed s/$SRCDATE/$DSTDATE/`
	if [ -f $DSTFILE ]
	then
		echo "WARNING: Destination $DSTFILE exists, moving to $DSTFILE.orig."
	fi

	echo "install -Dpb --suffix=.orig $f $DSTFILE"
	install -Dpb --suffix=.orig $f $DSTFILE
done
