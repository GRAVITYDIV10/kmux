#!/usr/bin/env bash

COUNT=100

while [ ${COUNT} -gt 0 ]
do
	dd bs=1M count=1 if=/dev/urandom of=rand &> /dev/null
	./kmux-tool -e < rand > rand.enc
	./kmux-tool -d < rand.enc > rand.dec
	suma=$(md5sum < rand | awk '{print $1}')
	sumb=$(md5sum < rand.dec | awk '{print $1}')
	echo $suma
	echo $sumb
	if [ "${suma}" != "${sumb}" ]
	then
		echo "TEST.FAIL"
		exit 1
	fi
	COUNT="$((COUNT - 1))"
done
