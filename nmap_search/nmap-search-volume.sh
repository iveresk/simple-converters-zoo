#!/usr/bin/env bash

REGIME=$1
IP=$2
PORT=$3

# Checking if we have a target to attack
if [ -z "$IP" ];then
	REGIME="-h"
fi

# Small standart how-to.
if [ -z "$REGIME" ] || [ "$REGIME" == "-h" ] || [ $REGIME == "--help" ];then
	echo "-------------------Welcome-to-big-nmap-script-by-1vere$k---------------+";
	echo "+----------------------------------------------------------------------+";
	echo "+-------------------For-The-Help---------------------------------------+";
	echo "Example#1: ./nmap-search-volume.sh -h----------------------------------+";
	echo "Example#2: ./nmap-search-volume.sh --help------------------------------+";
	echo "+-------------------For-The-URL-Check----------------------------------+";
	echo "Example#1: ./nmap-search-volume.sh -u <IP> <PORT> [Default PORT = 80--]+";
	echo "+-------------------For-The-File-Check---------------------------------+";
	echo "Example#1: ./nmap-search-volume.sh -f <FILENAME>-----------------------+";
	echo "+----------------------------------------------------------------------+";
	exit 1;
fi

# If PORT isn't mentioned - we stick the 80
if [ -z "$PORT" ]; then 
	PORT=80;
fi

# Attacking Target
if [ -e "$IP" ];then
	while read LINE; do
		echo "Making nmap -p $PORT $LINE";
		nmap -p $PORT $IP | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"
	done <$IP	
else
	echo "Making nmap -p $PORT $IP";
	nmap -p $PORT $IP | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"
fi