#!/bin/bash

# Script built by Johnathan Soto Spring 2019
# Script will convert cap files from the directory into pcap files and then convert them into SiLK Flow data to be stored
# in a sub directory called SilkFlow

# If wanting to specify directory
#echo "What directory houses the CTF team's pcap files? Please type the directory name:"
#read PDIR

mkdir SilkFlow
echo -e "\n-----------------------------------------------------------\nConverting cap files -> pcap files -> SiLK Flow files\n-----------------------------------------------------------"
for f in *.cap
do
  NAME=`echo "$f" | cut -d'.' -f1`
  echo "Processing $NAME.cap file..."
  # Convert cap files to  pcap files. $f store current cap file with extension and $NAME stores the general name
  editcap -F pcap $f $NAME.pcap
  # Use rwp2yaf2silk to convert the pcap to SiLK Flow data
  rwp2yaf2silk --in=$NAME.pcap --out=$NAME.rwf
  mv $NAME.rwf SilkFlow
  echo -e "$(pwd)/SilkFlow/$NAME.rwf" >> FlwLst.txt
done
mv FlwLst.txt SilkFlow
echo -e "\n-----------------------------------------------------------\nDone converting cap files -> pcap files -> SiLK Flow files\n-----------------------------------------------------------"
