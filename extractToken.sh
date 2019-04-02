#!/bin/bash

#echo "What directory houses the CTF team's pcap files? Please type the directory name:"
#read PDIR


python3 netPy.py 1
#cp nPy.py $PDIR
#cp TokRedWin.txt $PDIR
#cp RegExTok.txt $PDIR
#cd $PDIR
cp netPy.py NetTraffic
cp TokRedWin.txt NetTraffic
cp RegExTok.txt NetTraffic
cd NetTraffic


for d in $(ls -d */)
do
	NAME=`echo $d | cut -d "/" -f1`

	cp RegExTok.txt $d
	cp TokRedWin.txt $d
	cp netPy.py $d
	cd $d
	if [ -f KeyPcap.txt ]; then
		rm KeyPcap.txt
	fi
	if [ -f PcapTokenInNet.txt ]; then
        	rm PcapTokenInNet.txt
	fi
	# Execute filtering functions to get list of pcaps to check
	# Output will the list of pcaps that contain the tokens and also the list of tokens on the network
	# Saved in a txt file in each team's respective folders
	python3 netPy.py 2

	echo "Done with extraction of token for $NAME..."

	cd ..


done


