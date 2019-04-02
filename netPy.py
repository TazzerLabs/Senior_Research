# Created by Johnathan Soto Spring 2019
# Code will take a partial token file and tranforms them into Regular Expressions
# via adding '.' after every character in the token string, then output string into new file
# This will be used to help parse through PCAPs that have these RegEx and filter them to a designated area

# imported libraries
import datetime
import subprocess
import glob
import sys
import optparse
import argparse
import os

"""
 Functions: getPcapTime(Pcap, option)
            getPcapRanged(RedemptionInfo.txt)
            CreateRegEx(PartTok.txt, output)
            RegExFilter(Pcaplist, RegExlist.txt)

"""

def getPcapTime(pcapName, T=0):
    
    # if T = 0 then we are getting the Start Time of Pcap
    if T == 0:
        f = "-f"+str(2)
        q = "--fields="+str(6)+","+str(7)
    elif T == 1: # else if T == 1 then get the end times
        f = "-f"+str(3)
        q = "--fields="+str(7)+","+str(8)
    else:
        print ("Error: Invalid entry in getPcapTime(), got T -> ", T)

    E1 = subprocess.Popen(["capinfos", pcapName, "-a", "-e"], stdout=subprocess.PIPE)
    E2 = subprocess.Popen(["cut", "-d", "\n", f], stdin=E1.stdout, stdout=subprocess.PIPE)
    E1.stdout.close()
    E3 = subprocess.Popen(["cut", "-d", " ", q], stdin=E2.stdout, stdout=subprocess.PIPE)
    E2.stdout.close()
    #ETime = E3.communicate()[0].decode('utf-8').replace('\n', '')
    
    return ( E3.communicate()[0].decode('utf-8').replace('\n', '') )


# Filter the pcaps to those only containing the time frames that house the redeemption periods of the tokens
def getPcapRanged(RedFilename='TokRedWin.txt'):
  
    PCAPlist = []

    # For every pcap in the directory
    for pcaps in glob.glob("*.pcap"): # 306+ files for each team
        
        # Get the Start and end times for the pcap
        STime = getPcapTime(pcaps, 0)
        ETime = getPcapTime(pcaps, 1)

        # Transform string to dateTime
        StartTime = datetime.datetime.strptime(STime, '%Y-%m-%d %H:%M:%S.%f' )
        EndTime = datetime.datetime.strptime(ETime, '%Y-%m-%d %H:%M:%S.%f' )
   
        #Rfilename = input("Please enter Round file name here: ")
        #RedFilename = input("Please enter redemption file here: ")

        with open(RedFilename) as Red:
            for Redlines in Red: # 17869
                # do split here and dateTime conversion
                RedemptionTime = Redlines.split('\t')
                RStart = datetime.datetime.strptime(RedemptionTime[0], '%Y-%m-%d %H:%M:%S.%f')
                RedemptionTime = RedemptionTime[1].split('\n')
                REnd = datetime.datetime.strptime(RedemptionTime[0], '%Y-%m-%d %H:%M:%S.%f')
                    
                # if the Redemption times are within the pcap time, they might have a token
                if ( StartTime >= RStart and EndTime <= REnd ):
                    # Store filtered Pcaps in the list
                    PCAPlist.append(pcaps)

                # Puts Red cursor back to the top of file
            Red.seek(0)

    print ("End of getPcapRanged function")
    
    return PCAPlist


# Filters the pcap list even further by seeing which ones have a regular expression inside of the file themselves
def RegExFilter(pcapsList, inputF="RegExTok.txt"):

    RegExs = []

    with open(inputF) as f:
        for lines in f:
            line = lines.split('\n')
            RegExs.append(line[0])

    # for every pcap in the list
    with open("PcapTokenInNet.txt", 'w') as output:
        for pcaps in pcapsList:
            for RegEx in RegExs:
                # Check to see if the pcap has the Regular expression (Later will be a list of RegExs)
                E1 = subprocess.Popen(["ngrep", "-I", pcaps, RegEx, "-q"], stdout=subprocess.PIPE)
                E2 = subprocess.Popen(["wc", "-l"], stdin=E1.stdout, stdout=subprocess.PIPE)
                E1.stdout.close()
                E3 = E2.communicate()[0].decode('utf-8').replace('\n', '')
        

                Num_results = int(E3)

                # if the output is greater than 3 then we have a match somewhere
                if Num_results > 3:
                    print (pcaps, "\t", RegEx)
                    Result = subprocess.Popen(["ngrep", "-I", pcaps, RegEx, "-q"], stdout=subprocess.PIPE)
                    MatchInfo = Result.communicate()[0].decode('utf-8')
                    output.write(MatchInfo)
                    break



# Crates Regular expressions out of partial tokens extracted from the Postgres SQL database
def CreateRegEx(filename="PartTok.txt", output="RegExTok.txt"):

    #open file here
    with open(filename) as File, open(output, 'w') as output_file:
        for lines in File:
            string = '.'.join([lines[i:i+1] for i in range(0, len(lines), 1)])
            output_file.write(string)

    # return output file that has RegEx
    return output


#conv to function and have args putkeywords into functions tempfile

if __name__ == '__main__':



    parser = argparse.ArgumentParser(description='Program execute:\nCreateRegEx():\nthis function will generate a Regular Expression of partial Tokens given via user\ninput and output to a txt file given by user. If no files are given then the function will use default\nfiles for the input and output.\ngetPcapRanged():\nthis function will generate a Pcap file list from the current directory that houses the list of pcaps that\nare within the range of Round Start Time <= Pcap Time frame <= Redemption Time End.  This is done via\nuser inputing a Round information txt file, Redemption Time information, and a output folder name.  If no\nfiles or folders are given then function will use the default files for the input and output.')
    
    parser.add_argument('mode', type=int, help='Which functions you want to use:\n1 -> Partial Token to Regular Expression\n2 -> List of Pcaps within the range at which the token is on the wire')
    
    """ Experimental

    parser.add_argument('file1', type=str, action="store", dest="file1", nargs='?', help='File names of the txt files that the user wants to be inputed into their choice of function')
    parser.add_argument('file2', type=str, action="store", dest="file2", nargs='?', help='File name of output file for conversion of Partial token to RegEx OR the file for Redemption Token Info')
    parser.add_argument('file3', type=str, action="store", dest="file3", nargs='?', help='Output file if just getting Pcap range OR Round Information txt file if doing RegEx conversion and Pcap Range generation')
    parser.add_argument('file4', type=str, action="store", dest="file4", nargs='?', help='File names of the txt files that the user wants to be used for Redemption token info txt file')
    parser.add_argument('output-file', type=str, action="store", dest="output-file", nargs='?', help='Output file for when doing RegEx conversion and Pcap Range generation.  Output file for Pcaps within range')
    parser.add_argument('-o', type=int, nargs='?', help='Option of wheter to CreateRegEc() or getPcapRange(()...')
    parser.add_argument('--options=', type=int, nargs='?', help='If trying to do multiple functions within file...')

    parser.parse_args()

    #args, leftovers = parser.parse_known_args()


    if args.o > 3 and args.o <= 0:
        parser.error("-o can only be 1 or 2")

    """

    args = parser.parse_args()

    if args.mode == 1:
        CreateRegEx()
    elif args.mode == 2:
        RegExFilter(getPcapRanged())
    elif args.mode == 3:
        RegExFilter(getPcapRanged(), CreateRegEx())
    else:
        parser.error("Mode can only be a value of 1 or 2!\n")



