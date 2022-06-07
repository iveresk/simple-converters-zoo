#!/usr/bin/env bash

REGIME=$1
IP=$2
SEARCH="${3}"
PORT=$4

# Checking if we have a target to attack
if [ -z "$IP" ];then
	REGIME="-h"
fi

if [ -z "$SEARCH" ];then
        SEARCH=IIS
fi

# Small standart how-to.
if [ -z "$REGIME" ] || [ "$REGIME" == "-h" ] || [ $REGIME == "--help" ];then
	echo "-------------------------Welcome-to-nmap-iis-searcher-by-1veresk--------------------------------+";
	echo "+-----------------------------------------------------------------------------------------------+";
	echo "+-------------------For-The-Help----------------------------------------------------------------+";
	echo "Example#1: ./nmap-iis-searcher.sh -h------------------------------------------------------------+";
	echo "Example#2: ./nmap-iis-searcher.sh --help--------------------------------------------------------+";
	echo "+-------------------For-The-URL-Check-----------------------------------------------------------+";
	echo "Example#1: ./nmap-iis-searcher.sh -u <IP> <SEARCH TEXT> <PORT> [Default PORT = 80, SEARCH="IIS"]+";
	echo "+-------------------For-The-File-Check----------------------------------------------------------+";
	echo "Example#1: ./nmap-iis-searcher.sh -f <FILENAME> IIS 80------------------------------------------+";
	echo "+-----------------------------------------------------------------------------------------------+";
	exit 1;
fi

# If PORT isn't mentioned - we stick the 80
if [ -z "$PORT" ]; then 
	PORT=80;
fi

# Scanning Target
if [ -e "$IP" ];then
	nmap -T5 -p $PORT -iL $IP --script http-grep --script-args match=$SEARCH > "nmap_output.txt"
else
	nmap -T5 -p $PORT $IP --script http-grep --script-args match=$SEARCH > "nmap_output.txt"
fi

cat nmap_output.txt | egrep -o "\(1\) http://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | egrep -o "([0-9]{1,3}\.){3}[0-9]{1,3}" > "targets.txt"
cat nmap_output.txt | egrep -o "^.*http://.*" | sed 's/.*\/\///' | awk -F'/' '{print $1}' > "targets2.txt"
egrep -B 8 $SEARCH nmap_output.txt | egrep -o "([0-9]{1,3}\.){3}[0-9]{1,3}" > targets_full.txt
awk '!seen[$0]++' targets_full.txt > final.txt
