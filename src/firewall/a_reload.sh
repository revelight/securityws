#!/bin/bash
#set -x #echo on


# clean make
echo -e "\n\n===== make clean...\n"
make clean
echo -e "\n\n===== make...\n"
make

echo -e "\n\n"


# reload module
if [[ $1 != "" ]]
then
	echo -e "\n\n===== remove module...\n"
	rmmod $1.ko
	echo -e "\n\n===== insert module...\n"
	insmod $1.ko
fi


echo -e "\n\n"





