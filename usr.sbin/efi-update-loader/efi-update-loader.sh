#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2019 Rebecca Cran <bcran@FreeBSD.org>.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$

set -e

vout() {
	if [ -n "${verbose}" ]; then echo "$*"; fi
}


# Find the name of the default boot loader on the current architecture.
# This file is in the /EFI/BOOT directory on the ESP.
get_uefi_bootname() {
	case ${TARGET:-$(uname -m)} in
		amd64)	echo BOOTx64 ;;
		arm64)	echo BOOTaa64 ;;
		i386)	echo BOOTia32 ;;
		arm)	echo BOOTarm ;;
		*)
				echo "machine type $(uname -m) doesn't support UEFI"
				exit 1
		;;
	esac
}

 
clean_up() {
	trap 1 2 15 EXIT

	if [ -z "${mntpt}" ]; then exit 1; fi

	if mount | grep -q "${mntpt}" ; then
		umount "${mntpt}"
	fi

	if [ -d "${mntpt}" ]; then rmdir "${mntpt}"; fi

	echo "Something went wrong. The ESP(s) used were: ${esps}"
	echo "Any backups of the previous loader.efi and $(get_uefi_bootname).efi are in /tmp/espback.*"
}


# Determine whether /EFI/BOOT/BOOTxxx.efi is the FreeBSD boot1.efi or loader.efi executable.
bootefi_is_freebsd() {
	efibootname=$(get_uefi_bootname)
	
	if [ -f "${mntpt}/EFI/BOOT/${efibootname}.efi" ]; then
		# "FreeBSD EFI boot block" is contained in boot1.efi;
		# "FreeBSD/${arch} EFI loader" is contained in loader.efi
		loaderstring="FreeBSD/$(uname -m) EFI loader"
		boot1string="FreeBSD EFI boot block"
		if grep -q -e "${boot1string}" -e "${loaderstring}" "${mntpt}/EFI/BOOT/${efibootname}.efi"; then
			return 0
		fi
	fi

	return 1
}


# Find all ESPs on the same disk(s) as the root filesystem.
detect_esps() {
	mnt=/
	fsname=$(df "${mnt}" | tail -1 | cut -d ' ' -f 1)
	fstype=

	if df -t ufs "${mnt}" > /dev/null ; then
		fstype=ufs
	elif df -t zfs "${mnt}" > /dev/null ; then
		fstype=zfs
	else
		echo "Unsupported filesystem type"
		exit 1
	fi

	if [ "${fstype}" = "zfs" ]; then
		fslabel=$(df "${mnt}" | tail -1 | awk -F '[ /]' '{print $1}')
		zpool=$(zpool list -Hv "${fslabel}")
		totallines=$(echo "${zpool}" | wc -l)
		devlines=$(echo "${zpool}" | tail -$((totallines - 1)))
		labels=$(echo "${devlines}" | awk '{print $1}')
	elif [ "${fstype}" = "ufs" ]; then
		label=$(echo "${fsname}" | cut -c 6-256)

		for class in mirror raid raid3 vinum stripe virstor; do
			labels=$(geom ${class} status -s 2> /dev/null | grep "${label}" | awk '{print $3}') || true
			if [ -n "${labels}" ]; then
				break
			fi
		done
	fi

	for lbl in ${labels}; do
		lblout=$(geom label status -s | grep "${lbl}" | awk '{print $3}')
		if [ -n "${lblout}" ]; then
			dev="${lblout}"
		else
			dev="${lbl}"
		fi

		# Get the disk name from the partition/slice name
		disks="${disks} $(echo "${dev}" | awk -F '[ps]+[0-9]+' '{print $1}')"
	done

	for disk in ${disks}; do
		idx=$(gpart show "${disk}" 2> /dev/null | grep efi | awk '{print $3}')
		if [ -n "${idx}" ]; then
			if [ -e "/dev/${disk}p${idx}" ]; then
				esps="${esps} /dev/${disk}p${idx}"
			elif [ -e "/dev/${disk}s${idx}" ]; then
				esps="${esps} /dev/${disk}s${idx}"
			fi
		fi
	done

	if [ -n "${verbose}" ]; then
		echo -n "Found ESP(S): "
		for esp in ${esps}; do
			echo -n "${esp} "
		done
		echo
	fi
}


# Return the free disk space, in KB, on the mounted ESP.
get_freespace_on_esp() {
	df -k "${mntpt}" | tail -1 | awk '{print $4}'
}


copyloader() {
	mntpt=$(mktemp -d /tmp/esp.XXXXXX)
	espdev=$1

	mount -t msdosfs "${espdev}" "${mntpt}"

	ldrsize=$(stat -f %z "${loader}")
	ldrsize=$((ldrsize / 1024))

	efibootname=$(get_uefi_bootname)

	# Check we have enough space to install /EFI/BOOT/BOOT${arch}.efi
	if bootefi_is_freebsd; then
		existing_bootefi_size=$(stat -f %z "${mntpt}/EFI/BOOT/${efibootname}.efi")
		existing_bootefi_size=$((existing_bootefi_size / 1024))
		spaceneeded=$((existing_bootefi_size - ldrsize))
	fi

	if bootefi_is_freebsd && [ $(($(get_freespace_on_esp))) -lt ${spaceneeded} ]; then
		echo "Error: Insufficient space on ESP ${espdev} to install ${loader} as /EFI/FreeBSD/loader.efi"
		echo "Need ${spaceneeded}KB, but only $(($(get_freespace_on_esp))) remains."
		exit 1
	fi

	# Check we have enough space to install /EFI/FreeBSD/loader.efi
	if [ -f "${mntpt}/EFI/FreeBSD/loader.efi" ]; then
		existing_ldr_size=$(stat -f %z "${mntpt}/EFI/FreeBSD/loader.efi")
		existing_ldr_size=$((existing_ldr_size / 1024))
		spaceneeded=$((existing_ldr_size - ldrsize))
	fi

	if [ -f "${mntpt}/EFI/FreeBSD/loader.efi" ] && [ $(($(get_freespace_on_esp))) -lt ${spaceneeded} ]; then
		echo "Error: Insufficient space on ESP ${espdev} to install ${loader} to /EFI/BOOT/${efibootname}.efi."
		echo "Need ${spaceneeded}KB, but only $(($(get_freespace_on_esp))) remains."
		exit 1
	fi

	backdir=$(mktemp -d /tmp/espback.XXXXXX)

	# Make backups and copy the new loader
	if [ -f "${mntpt}/EFI/FreeBSD/loader.efi" ] && ! cmp -sz "${loader}" "${mntpt}/EFI/FreeBSD/loader.efi"; then
		cp "${mntpt}/EFI/FreeBSD/loader.efi" "${backdir}"
		eval vout "Copying ${loader} to /EFI/FreeBSD/loader.efi"
		cp "${loader}" "${mntpt}/EFI/FreeBSD/loader.efi"
		[ -f "${mntpt}/EFI/FreeBSD/loader-old.efi" ] && rm "${mntpt}/EFI/FreeBSD/loader-old.efi"
	elif [ -f "${mntpt}/EFI/FreeBSD/loader.efi" ]; then
		eval vout "${loader} is the same as /EFI/FreeBSD/loader.efi. Nothing to do."
	fi

	if bootefi_is_freebsd && ! cmp -sz "${loader}" "${mntpt}/EFI/BOOT/${efibootname}.efi"; then
		cp "${mntpt}/EFI/BOOT/${efibootname}.efi" "${backdir}/${efibootname}.efi"
		eval vout "Copying ${loader} to /EFI/BOOT/${efibootname}.efi"
		cp "${loader}" "${mntpt}/EFI/BOOT/${efibootname}.efi"
		[ -f "${mntpt}/EFI/BOOT/${efibootname}-old.efi" ] && rm "${mntpt}/EFI/BOOT/${efibootname}-old.efi"
	elif bootefi_is_freebsd; then
		eval vout "${loader} is the same as /EFI/BOOT/${efibootname}.efi. Nothing to do."
	fi

	# Copy backups to the ESP
	if [ -f "${backdir}/loader.efi" ]; then
		sz=$(stat -f %z "${backdir}/loader.efi")
		sz=$((sz / 1024))
		if [ $(($(get_freespace_on_esp))) -gt ${sz} ]; then
			eval vout "Backing up previous /EFI/FreeBSD/loader.efi to /EFI/FreeBSD/loader-old.efi"
			cp "${backdir}/loader.efi" "${mntpt}/EFI/FreeBSD/loader-old.efi"
		else
			eval vout "Skipping backup of previous /EFI/FreeBSD/loader.efi due to insufficient disk space."
		fi
	fi

	if [ -f "${backdir}/${efibootname}.efi" ]; then
		sz=$(stat -f %z "${backdir}/${efibootname}.efi")
		sz=$((sz / 1024))
		if [ $(($(get_freespace_on_esp))) -gt ${sz} ]; then
			eval vout "Backing up previous /EFI/BOOT/${efibootname}.efi to /EFI/BOOT/${efibootname}-old.efi"
			cp "${backdir}/${efibootname}.efi" "${mntpt}/EFI/BOOT/${efibootname}-old.efi"
		else
			eval vout "Skipping backup of previous /EFI/BOOT/${efibootname}.efi due to insufficient disk space."
		fi
	fi

	umount "${mntpt}"
	rmdir "${mntpt}"
	if [ -f "${backdir}/loader.efi" ]; then rm "${backdir}/loader.efi"; fi
	if [ -f "${backdir}/${efibootname}.efi" ]; then rm "${backdir}/${efibootname}.efi"; fi
	if [ -d "${backdir}" ]; then rmdir "${backdir}"; fi
}


usage() {
	printf 'usage: %s [-d device] [-l loader] [-v]\n' "${progname}"
	printf '\t-d device\tEFI System Partition (ESP) device name\n'
	printf '\t-l loader\tFreeBSD EFI loader (default is /boot/loader.efi)\n'
	printf '\t-v \t\tEnable verbose output\n'
	exit 0
}


progname=$0
loader=/boot/loader.efi

while getopts "vd:l:h" opt; do
	case "$opt" in
		d)
			esps=${OPTARG}
			;;
		l)
			loader=${OPTARG}
			;;
		v)
			verbose=1
			;;
		?)
			usage
			;;
	esac
done

trap clean_up 1 2 15 EXIT

# If the user didn't specify a device to update, look for any ESPs on the same
# disk(s) as the root filesystem.
if [ -z "${esps}" ]; then

	eval detect_esps

	if [ -z "${esps}" ]; then
		echo "Error: could not detect ESP containing FreeBSD loader to update"
		exit 1
	fi
fi

if [ -z "${esps}" ]; then
	eval usage	
	exit 1
fi

for esp in ${esps}; do
	eval copyloader "${esp}" "${loader}"
done

trap 1 2 15 EXIT
