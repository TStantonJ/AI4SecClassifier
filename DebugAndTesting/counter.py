from importlib.resources import files
import sys
import os
import json
import gzip
from pathlib import Path
import re
#from tempfile import tempdir




# Convert compressed json file into compressed line seperated json file
# Takes location of inital gzipped json file
def proc():
    ipDict = {}
    # First argument is the jq file name
    if len(sys.argv) <= 1:
        print ("Missing json file")
        print ('Usage: '+sys.argv[0]+" <json file>")
        sys.exit(-1)

    try:
        # IMPORTANT
        counter = 0
        inName = Path(sys.argv[1]).resolve().stem
        in_handle = gzip.open(sys.argv[1], 'r')
        record = ''
        obj = ''


        # Not IMPORTANT
        num = 0
        totalPackets = 0
        totalInterestingPackets = 0
        #ipDict = {}

        #Loop through every line in the file
        for line in in_handle:
            #IMPORTANT
            totalPackets += 1
            #Convert line to json object
            jsonObj = json.loads(line)





            #NOT IMPORTANT (CHANGE THIS TO HUNT FOR INFO)
            #Search for information in each json object
            if 'icmp' in jsonObj['_source']['layers']:
                if jsonObj['_source']['layers']['icmp']['icmp.type'] == '8':
                    totalInterestingPackets += 1
                    if ipDict.get(jsonObj['_source']['layers']['ip']['ip.src']) != None:
                            tmp = ipDict.get(jsonObj['_source']['layers']['ip']['ip.src'])
                            ipDict[jsonObj['_source']['layers']['ip']['ip.src']] = tmp + 1
                    else:
                            ipDict[jsonObj['_source']['layers']['ip']['ip.src']] = 1
            





            #IMPORTANT(ENDS FILE BEFORE REACHING ERROR IN COMPRESSION)
            counter += 1
            jsonObj = None
            if counter >= 800000:
                break

        #INFORMAITON READOUT
        print('Scanned '+str(counter)+' objects')
        print(ipDict)
        print('Total Interesting Packets: ' + str(totalInterestingPackets))

    #IO ERROR HANDLE
    except (IOError, KeyError) as e:
        print('Failed on item ' + str(counter))
        print (str(e))
        sys.exit(-1)


# Scan
def icmpPacketEnum():

    icmpTypeDict = {}

    # First argument is the jq file name
    if len(sys.argv) <= 1:
        print ("Missing json file")
        print ('Usage: '+sys.argv[0]+" <json file>")
        sys.exit(-1)

    try:
        counter = 0
        inName = Path(sys.argv[1]).resolve().stem
        
        #Open given file
        in_handle = gzip.open(sys.argv[1], 'r')
        record = ''
        obj = ''
        num = 0
        totalPackets = 0
        totalInterestingPackets = 0
        #ipDict = {}

        #Loop through every line in the file
        for line in in_handle:
            totalPackets += 1
            #line = line.rstrip()
            #record = line.decode('utf-8')
            
            #Convert line to json object
            jsonObj = json.loads(line)

            #Search for information in each json object

            #looking for ssh(TCP:port 22) calls
            if 'icmp' in jsonObj['_source']['layers']:
                if jsonObj['_source']['layers']['ip']['ip.src'] == '10.0.0.1':
                    totalInterestingPackets += 1
                    if icmpTypeDict.get(jsonObj['_source']['layers']['icmp']['icmp.type']) != None:
                            tmp = icmpTypeDict.get(jsonObj['_source']['layers']['icmp']['icmp.type'])
                            icmpTypeDict[jsonObj['_source']['layers']['icmp']['icmp.type']] = tmp + 1
                    else:
                            icmpTypeDict[jsonObj['_source']['layers']['icmp']['icmp.type']] = 1
            #print(jsonObj)
            #tmp = json.dumps(tmp)
            
            counter += 1
            jsonObj = None
            if counter >= 800000:
                break
        print('Scanned '+str(counter)+' objects')
        print(icmpTypeDict)
        print('Total Interesting Packets: ' + str(totalInterestingPackets))
        #return jsonObj




    except (IOError, KeyError) as e:
        print('Failed on item ' + str(counter))
        print (str(e))
        sys.exit(-1)

# Get a detailed list of who is accessing ssh 
# Takes a folder containing every file to check
# Returns a printed list of information
def sshInformation(directory = '/Users/trs/Documents/GitHub/AI4SecClassifier/runFilesAlt'):
    
    # First argument is the directory of files
    '''
    if len(sys.argv) <= 1:
        print ("Missing directory path")
        print ('Usage: '+sys.argv[0]+" <path>")
        sys.exit(-1)
    '''
    try:
        filesTested = 0
        sortedFiles = sorted((f for f in os.listdir(directory) if not f.startswith(".")), key=str.lower)
        for file in sortedFiles:
            # Get current file and check its appropriate
            filename = os.fsdecode(file)
            if filename.endswith(".json.gz") or filename.endswith(".json"): 
                filesTested += 1

                # Process Json File
                counter = 0
                print(filename)
                in_handle = gzip.open(os.path.join(directory, file), 'r')
                record = ''
                obj = ''
                ipDict = {}
                frequencyDict = {}
                resetDict = {}
                kexDict = {}
                totalPackets = 0
                totalInterestingPackets = 0

                httpDict ={}

                for line in in_handle:
                    #IMPORTANT
                    line = line.decode('utf-8')
                    totalPackets += 1
                    #Convert line to json object
                    jsonObj = json.loads(line)

                    #Search/Enumerate for ssh requests 
                    
                    if 'tcp' in jsonObj['_source']['layers']:
                        if jsonObj['_source']['layers']['tcp']['tcp.dstport'] == '22':
                            totalInterestingPackets += 1
                            if ipDict.get(jsonObj['_source']['layers']['ip']['ip.src']) != None:
                                    tmp = ipDict.get(jsonObj['_source']['layers']['ip']['ip.src'])
                                    ipDict[jsonObj['_source']['layers']['ip']['ip.src']] = tmp + 1
                            else:
                                    ipDict[jsonObj['_source']['layers']['ip']['ip.src']] = 1
                    tmp = 0
                    '''
                    try:
                        if 'http' in jsonObj['_source']['layers']:
                                totalInterestingPackets += 1
                                if ipDict.get(jsonObj['_source']['layers']['ip']['ip.src']) != None:
                                        tmp = ipDict.get(jsonObj['_source']['layers']['ip']['ip.src'])
                                        ipDict[jsonObj['_source']['layers']['ip']['ip.src']] = tmp + 1
                                else:
                                        ipDict[jsonObj['_source']['layers']['ip']['ip.src']] = 1

                                if httpDict.get(jsonObj['_source']['layers']['ip']['ip.src']) != None:
                                        tmp = re.sub('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))',  '', str(httpDict.get(jsonObj['_source']['layers']['ip']['ip.src'])), flags=re.MULTILINE)
                                        #tmp = str(httpDict.get(jsonObj['_source']['layers']['ip']['ip.src']))
                                        httpDict[jsonObj['_source']['layers']['ip']['ip.src']] = tmp + str(jsonObj['_source']['layers']['http']['http.request.full_uri']) + ', '
                                else:
                                        httpDict[jsonObj['_source']['layers']['ip']['ip.src']] = re.sub('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))',  '', str(httpDict.get(jsonObj['_source']['layers']['ip']['ip.src'])), flags=re.MULTILINE)

                        tmp = 0
                    except:
                        continue
                    '''


                    #Enumerate how often IP addresses send packets
                    if 'ip' in jsonObj['_source']['layers']:
                        if frequencyDict.get(jsonObj['_source']['layers']['ip']['ip.src']) != None:
                                tmp = frequencyDict.get(jsonObj['_source']['layers']['ip']['ip.src'])
                                frequencyDict[jsonObj['_source']['layers']['ip']['ip.src']] = tmp + 1
                        else:
                                frequencyDict[jsonObj['_source']['layers']['ip']['ip.src']] = 1
                        if 'tcp' in jsonObj['_source']['layers']:
                            if jsonObj['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.reset'] == '1':
                                if resetDict.get(jsonObj['_source']['layers']['ip']['ip.dst']) != None:
                                        tmp = resetDict.get(jsonObj['_source']['layers']['ip']['ip.dst'])
                                        resetDict[jsonObj['_source']['layers']['ip']['ip.dst']] = tmp + 1
                                else:
                                        resetDict[jsonObj['_source']['layers']['ip']['ip.dst']] = 1
                        '''
                            if 'ssh' in jsonObj['_source']['layers']['tcp']:
                                if jsonObj['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.reset'] == '1':
                                    if resetDict.get(jsonObj['_source']['layers']['ip']['ip.dst']) != None:
                                            tmp = resetDict.get(jsonObj['_source']['layers']['ip']['ip.dst'])
                                            resetDict[jsonObj['_source']['layers']['ip']['ip.dst']] = tmp + 1
                                    else:
                                            resetDict[jsonObj['_source']['layers']['ip']['ip.dst']] = 1
                        '''
                            
                    #IMPORTANT(ENDS FILE BEFORE REACHING ERROR IN COMPRESSION)
                    counter += 1
                    jsonObj = None
                    if counter >= 800000:
                        break

                print('Scanned '+str(counter)+' objects')
                print(ipDict)
                print('Total Interesting Packets: ' + str(totalInterestingPackets))
            else:
                print('Failed' + filename)
                #continue


           
            if filesTested > 0:
                '''
                for item in httpDict:
                    print(item)
                    print(httpDict.get(item))
                '''
                #Print out file's results
                ipHolder = 'IP'
                sshHolder = 'SSH sends'
                totalHolder = 'Total sends'
                resetHolder = 'Total Attempts reset'
                print("{:30s}{:30s}{:30s}{:30s}".format(ipHolder,sshHolder,totalHolder,resetHolder))
                outputOrder = sorted(ipDict, key=ipDict.get, reverse=True)
                #print(outputOrder)
                for item in range(len(outputOrder)):
                    key = outputOrder[item]
                    value = ipDict.get(outputOrder[item])
                    auxValue = frequencyDict.get(outputOrder[item])
                    resetValue = resetDict.get(outputOrder[item])

                    if resetValue == None:
                        resetValue = 0

                    print("{:12s}{:30f}{:30f}{:30f}".format(key,value,auxValue,resetValue))
                
        pass





    except (IOError, KeyError) as e:
        #print('Failed on file ' + str(counter))
        #print (str(e))
        #sys.exit(-1)
        pass



if __name__ == '__main__':
    #icmpPacketEnum()
    #proc()
    sshInformation()