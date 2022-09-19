#!/usr/bin/env bash

IP=$1
PING="fping-scan.txt"

if [ -z "$IP" ];then
    echo "enter an IP for the scan"
fi

rm $PING

if [[ $IP =~ ^(([0-9]{1,3})\.){1,3}([0-9]{1,3})\/([0-9]+) ]];then
	fping -a -g -r 1 $IP > $PING
fi

if [ -e "$IP" ]; then
	fping -a -g -r 1 -f $IP > $PING
fi


if [ -e "$PING" ]; then
	nmap -Pn -sV -p 5060,21,22,23,80,443,444,139,445,8291,8290,554 -iL $PING > winjs-output.txt
else
	nmap -Pn -sV -p 5060,21,22,23,80,443,444,139,445,8291,8290,554 $IP > winjs-output.txt
fi

cat winjs-output.txt | grep -B 7 "open"
