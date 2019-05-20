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
import re

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
def RegExFilter(pcapsList, inputF="RegExTok.txt", output="PcapTokenInNet.txt"):

    RegExs = []

    with open(inputF) as f:
        for lines in f:
            line = lines.split('\n')
            RegExs.append(line[0])

    # for every pcap in the list
    with open(output, 'w') as output:
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

# Will extract payload from the tcpstream and put inside a pcapNameFlow.txt file that houses the payload
# which will have the exploits inside of them
def extractPayload(filename="PcapTokenInNet.txt", serviceID='HTTP/1.1 200 OK', output="Flow.txt"):

    # These are the usual output leads from the ngrep command executed in the previous run
    # Just need to parse through ngrep output to find gems that (when pushed through tcpflow) 
    # will give a conversation between the src ip and dst ip during the game for a specific service 
    # identifer
    Input = 'input: '
    match = 'match: '
    IP = 'T '
    tcpFlowRecords = []
    regex = []

    # Parses through the matching flag data and pinpoints pcap names, ips, regexs, and
    # service identification pattern, for eliza: HTTP/1.1 200 OK and
    # extracts payload for further analysis
    with open(output, 'r') as file:
        lines = file.readlines()
        for i in range(len(lines)):
            if Input in lines[i]:
                a = lines[i].split(Input)
                pcapName = a[1]
                pcapName = pcapName.split("\n")[0]
                teamflow = pcapName.split(".")[0]
                teamflow = teamflow + output
                if match in lines[i+2]:
                    m = lines[i+2].split(match)
                    regex.append(m[1])
                    if IP in lines[i+4]:
                        b = lines[i+4].split(IP)
                        b = b[1].split(" -> ")
                        sip = b[0]
                        sip = sip.split(":")[0]
                        b = b[1].split(" [")
                        dip = b[0]
                        dip = dip.split(":")[0]
                        if serviceID in lines[i+5]:
                            with  open (teamflow, 'w+') as f:
                                print ("executing tcpflow")
                                cmd = "tcpflow -r " + pcapName + " -c host " + sip + " and " + dip + " > " + teamflow
                                flowProc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                                flowProc.communicate(input='\n')
                            tcpFlowRecords.append(teamflow)


    # Cut off the extra data from the output and have exact data from eliza service exploit used in game
    #if serviceID == 'HTTP/1.1 200 OK':
    #    extractEliza(tcpFlowRecords, regex)
    # may have output that is a txt file so just now invent a function that will learn polymorphisms of this exploit...


# Will be able to cut out excess data from the payload and fully have exploit to be parsed for any polymorphisms from other eliza variations
def extractEliza(tcpFlows, partialToken):

    Flag = ""
    exploit = []

    with open(tcpFlows, 'r') as Flow:
        for lines in Flow:
            line = lines.rstrip()

            #Find the start of the exploit
            if re.search('SELECT', line):
                
                for subLines in lines:
                    subLine = subLines.rstrip()

                    # Exploit contains help then info eliza, then GET, then flag
                    if re.search('help', subLine):
                        
                        for subs in subLines:
                            sub = subs.rstrip()

                            if re.search('info', sub):

                                for subbs in subs:
                                    subb = subb.rstrip()

                                    if re.search('GET', subb):

                                        for liners in subbs:
                                            liner = liners.rstrip()

                                             # Find flag and the end of the exploit
                                            if re.search(partialToken, liner):
                                                exploit.append(line)
                                                exploit.append(subLine)
                                                exploit.append(sub)
                                                exploit.append(subb)
                                                exploit.append(liner)
                                                Flag = liner
                                                break

    # exploit has the eliza exploit used to get the flag + the flag
    # and Flag has the flag that was captured (extra data)
    print (exploit)


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
    elif args.mode == 4:
        tcpflowRecorder = extractPayload()
        # Call function to extractEliza()
    elif args.mode == 5: # for the user specified
        inputf = input("What partial flag txt file do you want converted to a Regular expression txt file? ")
        outf = input("What name do you want to give the output file? ")
        CreateRegEx(inputf, outputf)
        winInf = input("What txt file has the time windows for the relavant pcaps? ")
        regOutf = input("What filename do you want to give for the file that will have the flag in the network? ")
        RegExFilter(getPcapRanged(winInf), outf, regOutf)
        inputPayload = input("What txt file contains the ngrep output of the Pcpaps and Flags on the network? ")
        inputService = input("What service are we searching for? ")
        outputExtract = input("What output txt file do you want the tcpflow in? ")
        extractPayload(inputPayload, inputService, outputExtract)
    elif args.mode == 6: #Eliza
        RegExFilter(getPcapRanged(), CreateRegEx( "elizaTok.txt", "elizaRegExTok.txt" ), "elizaGrep.txt")
        extractPayload("elizaGrep.txt")
    else:
        parser.error("Modes available are:\n 1) CreateRegEx\n2) RegExFilter & getPcapRanged\n3) RegExFilter & getPcapRanged & CreateRegEx\n 4) extractPayload\n5) User input mode\n")



