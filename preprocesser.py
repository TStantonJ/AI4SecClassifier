import array
from cProfile import label
import sys
import os
import json
import gzip
from pathlib import Path
import re
import math

# Data Order: Port, source IP, dest IP,
def preprocess(directory = './preprocessFiles'):

    try:
        with gzip.open('./classifierFiles/goodData.gz', 'w') as good_data_out:
            with gzip.open('./classifierFiles/badData.gz', 'w') as bad_data_out:
                
                # Process every file in proccess directory
                sortedFiles = sorted((f for f in os.listdir(directory) if not f.startswith(".")), key=str.lower)
                for file in sortedFiles:
                    # Get current file and check its appropriate
                    filename = os.fsdecode(file)


                    # Get/store Meta Data from current file
                    meta_dict = getMetaData(directory, file)

                    in_handle = gzip.open(os.path.join(directory, file), 'r')
                    for line in in_handle:

                        # ---Setup---
                        # Check variables
                        bad_flag = False
                        ssh_flag = False

                        # Decode and convert line to json obj
                        line = line.decode('utf-8')
                        jsonObj = json.loads(line)


                        # ---Data Processing---
                        # Perform checks
                        if ssh_check(jsonObj):
                            bad_flag = True
                        


                        # Assign relevant data to variables
                        # TCP Ports
                        if 'tcp' in jsonObj['_source']['layers']:
                            tcp_src = jsonObj['_source']['layers']['tcp']['tcp.srcport']
                            tcp_dst = jsonObj['_source']['layers']['tcp']['tcp.dstport']
                        else:
                            tcp_src = '0'
                            tcp_dst = '0'

                        # IP addresses
                        if 'ip' in jsonObj['_source']['layers']:
                            ip_src = jsonObj['_source']['layers']['ip']['ip.src']
                            ip_dst = jsonObj['_source']['layers']['ip']['ip.dst']

                            src_parts = ip_src.split('.')
                            new_ip_src = ''
                            for sub_part in range(4):
                                if len(src_parts[sub_part]) == 3:
                                    new_ip_src += src_parts[sub_part]
                                elif len(src_parts[sub_part]) == 2:
                                    new_ip_src += '0'+ src_parts[sub_part]
                                else:
                                    new_ip_src += '00' + src_parts[sub_part]
                            
                            dst_parts = ip_dst.split('.')
                            new_ip_dst = ''
                            for sub_part in range(4):
                                if len(dst_parts[sub_part]) == 3:
                                    new_ip_dst += dst_parts[sub_part]
                                elif len(dst_parts[sub_part]) == 2:
                                    new_ip_dst += '0'+ dst_parts[sub_part]
                                else:
                                    new_ip_dst += '00' + dst_parts[sub_part]
                        else:
                            new_ip_src = '0'
                            new_ip_dst = '0'


                        # ---Data Out---
                        # New line encoded variable (for data seperation)
                        new_line = '\n'
                        new_line_encoded = new_line.encode('utf-8')

                        # Create string containing recorded data
                        data_string = tcp_src
                        data_string += ','
                        data_string += tcp_dst
                        data_string += ','
                        data_string += new_ip_src
                        data_string += ','
                        data_string += new_ip_dst

                        # Convert data string to bytes
                        data_string_encoded = data_string.encode('utf-8')


                        # Add data to bad or good data file
                        if bad_flag:
                            bad_data_out.write(data_string_encoded)
                            bad_data_out.write(new_line_encoded)
                        else:
                            good_data_out.write(data_string_encoded)
                            good_data_out.write(new_line_encoded)
                        
        # Close files
        good_data_out.close()
        bad_data_out.close()

    except (IOError, KeyError) as e:
        print(str(e))
        pass


# ---Functions to Check conditions go here---
def ssh_check(_obj):
    if 'tcp' in _obj['_source']['layers']:
        if _obj['_source']['layers']['tcp']['tcp.dstport'] == '22':
            return True
    return False




# ---Collect General Data from file---
def getMetaData(_directory, _file):
    try:
        ret_ip_dict = {}
        data_handle = gzip.open(os.path.join(_directory, _file), 'r')

        # Itterate through every Packet get its data from it
        for line in data_handle:
            # Decode and convert line to json obj
            line = line.decode('utf-8')
            jsonObj = json.loads(line)

            if 'ip' in jsonObj['_source']['layers']:
                src = jsonObj['_source']['layers']['ip']['ip.src']
                dst = jsonObj['_source']['layers']['ip']['ip.dst']
                
                # Recording total number of sent packets, total number of recieved packets, and log src->dst communication
                if ret_ip_dict.get(src) == None:
                    ret_ip_dict[src] = {'totalSent': 1, 'totalRecieved': 0}
                    ret_ip_dict[src][dst] = 1
                else:
                    ret_ip_dict[src]['totalSent'] = ret_ip_dict[src].get('totalSent') + 1
                    ret_ip_dict[src]['totalRecieved'] = ret_ip_dict[src].get('totalRecieved')+ 1
                    if ret_ip_dict[src].get(dst) == None:
                        ret_ip_dict[src][dst] = 1
                    else:
                        ret_ip_dict[src][dst] = ret_ip_dict[src].get(dst) + 1
    except:
        pass
    return ret_ip_dict


if __name__ == '__main__':
    preprocess()