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
	echo "-----------------Welcome-to-nmap-iis-searcher-by-1veresk---------------+";
	echo "+----------------------------------------------------------------------+";
	echo "+-------------------For-The-Help---------------------------------------+";
	echo "Example#1: ./nmap-iis-searcher.sh -h-----------------------------------+";
	echo "Example#2: ./nmap-iis-searcher.sh --help-------------------------------+";
	echo "+-------------------For-The-URL-Check----------------------------------+";
	echo "Example#1: ./nmap-iis-searcher.sh -u <IP> <PORT> [Default PORT = 80---]+";
	echo "+-------------------For-The-File-Check---------------------------------+";
	echo "Example#1: ./nmap-iis-searcher.sh -f <FILENAME>------------------------+";
	echo "+----------------------------------------------------------------------+";
	exit 1;
fi

# If PORT isn't mentioned - we stick the 80
if [ -z "$PORT" ]; then 
	PORT=80;
fi

# Scanning Target
if [ -e "$IP" ];then
	nmap -T5 -p $PORT -iL $IP --script http-grep --script-args='match="IIS"' > "output.txt"
else
	nmap -T5 -p $PORT $IP --script http-grep --script-args='match="IIS"' > "output.txt"
fi

cat output.txt | egrep -o "\(1\) http://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | egrep -o "([0-9]{1,3}\.){3}[0-9]{1,3}" > "targets.txt"