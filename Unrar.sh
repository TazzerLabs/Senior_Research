#!/bin/bash

# Script built by Johnathan Soto
# Script will open all rar files in the directory for the Defcon teams and will then
# move them all into a sub directory called NetTraffic

#echo "Please specify what directory you want to store the Team cap/Pcaps in: "
#read PDIR
#mkdir $PDIR

mkdir NetTraffic
echo "Opening rar files and moving to folder NetTraffic in subfolder with their respective names"
for r in *.rar
do    
  NAME=`echo "$r" | cut -d'.' -f1`	
  echo -e "\nOpening $r...\n"	
  unrar e $r
  #mkdir $PDIR/$NAME
  #mv *.cap $PDIR/$NAME
  #cp CapConv.sh $PDIR/$NAME
  mkdir NetTraffic/$NAME
  mv *.cap NetTraffic/$NAME
  cp CapConv.sh NetTraffic/$NAME  
  ./CapConv.sh
  cd ../..
  # Now make line from Flow data via flowplotter
  echo -e "\n--------------------------------------------------------------------------\nFiltering SiLK Flow Data and producing a linechart for each team\n--------------------------------------------------------------------------"
  #rwfilter --all-destination=stdout --print-statistics --xargs=$(pwd)/$PDIR/$NAME/SilkFlow/FlwLst.txt | ./flowplotter.sh linechart 60 packets > $NAME-linechart.csv
  rwfilter --all-destination=stdout --print-statistics --xargs=$(pwd)/NetTraffic/$NAME/SilkFlow/FlwLst.txt | ./flowplotter.sh linechart 60 packets > $NAME-linechart.csv 
  
  #cat $NAME-linechart.csv | head --lines=$(expr `grep -n "]);$" $NAME-linechart.csv | cut -d : -f 1` - 1) | tr -d '[]' | tail --lines=+`grep -n "'stime','packets'" $NAME-linechart.csv | cut -d : -f 1` | less
  
  echo -e "\n--------------------------------------------------------------------------\nDone filtering SiLK Flow Data and producing a linechart for each team\n--------------------------------------------------------------------------"
done
