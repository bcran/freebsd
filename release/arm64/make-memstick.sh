#!/bin/sh
#
# This script generates a "memstick image" (image that can be copied to a
# USB memory stick) from a directory tree.  Note that the script does not
# clean up after itself very well for error conditions on purpose so the
# problem can be diagnosed (full filesystem most likely but ...).
#
# Usage: make-memstick.sh <directory tree> <image filename>
#
# $FreeBSD$
#

set -e

PATH=/bin:/usr/bin:/sbin:/usr/sbin
export PATH

if [ $# -ne 2 ]; then
	echo "make-memstick.sh /path/to/directory /path/to/image/file"
	exit 1
fi

if [ ! -d ${1} ]; then
	echo "${1} must be a directory"
	exit 1
fi

if [ -e ${2} ]; then
	echo "won't overwrite ${2}"
	exit 1
fi

echo '/dev/ufs/FreeBSD_Install / ufs ro,noatime 1 1' > ${1}/etc/fstab
echo 'root_rw_mount="NO"' > ${1}/etc/rc.conf.local
makefs -B little -o label=FreeBSD_Install -o version=2 ${2}.part ${1}
rm ${1}/etc/fstab
rm ${1}/etc/rc.conf.local


dd if=/dev/zero of=efiboot.img bs=1k count=33292
device=`mdconfig -a -t vnode -f efiboot.img`
newfs_msdos -F 32 -c 1 -L EFISYS /dev/$device
mkdir efi
mount -t msdosfs /dev/$device efi
mkdir -p efi/efi/boot
cp -p "${1}/boot/loader.efi" efi/efi/boot/bootaa64.efi
umount efi
rmdir efi
mdconfig -d -u $device


mkimg -s gpt \
    -p efi:=efiboot.img \
    -p freebsd:=${2}.part \
    -o ${2}
rm efiboot.img
rm ${2}.part

