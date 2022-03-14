import array
from ast import Return
from cProfile import label
import sys
import os
import json
import gzip
from pathlib import Path
import re
import math

# Data Order: Port, source IP, dest IP,
def preprocess(directory = './preprocesserFiles'):
    try:
        with gzip.open('./classifierFiles/goodData.gz', 'w') as good_data_out:
            with gzip.open('./classifierFiles/badData.gz', 'w') as bad_data_out:
                # Process every file in proccess directory
                sortedFiles = sorted((f for f in os.listdir(directory) if not f.startswith(".")), key=str.lower)
                
                for file in sortedFiles:
                    
                    # Get current file and check its appropriate
                    filename = os.fsdecode(file)


                    # Get/store Meta Data from current file
                    meta_dict, tcp_meta_dict, http_meta_dict = getMetaData(directory, file)
                    # Item tracking for debug/Arrays to check outputs
                    item_number = 0
                    good_data_numbers = [430,431,432,433,434,435,436,437,438]
                    bad_data_numbers = [700,701,702,703,704,708,709,710]

                    in_handle = gzip.open(os.path.join(directory, file), 'r')
                    for line in in_handle:
                        item_number += 1

                        # ---Setup---
                        # Check variables
                        bad_flag = False
                        ssh_flag = False

                        # Decode and convert line to json obj
                        line = line.decode('utf-8')
                        jsonObj = json.loads(line)


                        # ---Data Processing---
                        
                        # Assign relevant data to variables
                        # IP addresses
                        if 'ip' in jsonObj['_source']['layers']:
                            ip_src = jsonObj['_source']['layers']['ip']['ip.src']
                            ip_dst = jsonObj['_source']['layers']['ip']['ip.dst']

                            #Catch 127.0.0.1
                            if ip_dst == '127.0.0.1' or ip_src == '127.0.0.1':
                                continue
                            if ip_src == ip_dst:
                                continue

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
                        # TCP Ports
                        if new_ip_src != '0':
                            if 'tcp' in jsonObj['_source']['layers']:
                                tcp_src = str(jsonObj['_source']['layers']['tcp']['tcp.srcport'])
                                tcp_dst = str(jsonObj['_source']['layers']['tcp']['tcp.dstport'])
                            else:
                                tcp_src = '0'
                                tcp_dst = '0'
                        else:
                            tcp_src = '0'
                            tcp_dst = '0'

                        # SSH bruteforce features(Ratio of tcp dst port 22 packets to total packets)
                        # Get total packets sent by src
                        if new_ip_src != '0':
                            total_packets_sent = str(meta_dict[ip_src].get('totalSent'))
                        else:
                            total_packets_sent = '0'
                        # Get total dst port 22 packets sent by src and then get ratio of 22 to total
                        if new_ip_src != '0':
                            if 'tcp' in jsonObj['_source']['layers']:
                                if tcp_meta_dict[ip_src][ip_dst].get('22') == None:
                                    tcp_SSH_ratio = '0'
                                else:
                                    tcp_SSH_count = tcp_meta_dict[ip_src][ip_dst].get('22')
                                    tcp_total_count = 0
                                    for port in tcp_meta_dict[ip_src][ip_dst]:        
                                        tcp_total_count += tcp_meta_dict[ip_src][ip_dst].get(port)
                                    tcp_SSH_ratio = str(tcp_SSH_count/tcp_total_count)
                            else:
                                tcp_SSH_ratio = '0'
                        else:
                            tcp_SSH_ratio = '0'
                        
                        

                        # Port scanning(Ratio of tcp syns(only) to tcp acks(only))
                        # Get the total acks and syns between the two IPs(Probably unnecessary but need to ask group)
                        '''
                        if new_ip_src != '0':
                            if 'tcp' in jsonObj['_source']['layers']:
                                tcp_syns = str(tcp_meta_dict[ip_src][ip_dst]['syn'])
                                if ip_dst in tcp_meta_dict:             # WE KNOW IF AN IP TRIES TO COMMUNICATED WITH AN IP THAT DOESNT EVER TALK TO ANYONE EVER
                                    if ip_src in tcp_meta_dict[ip_dst]:

                                        tcp_acks = str(tcp_meta_dict[ip_dst][ip_src]['ack'])
                                    else:
                                        tcp_acks = '0'
                                else:
                                    tcp_acks = '0'
                            else:
                                tcp_syns = '0'
                                tcp_acks = '0'
                        else:
                            tcp_syns = '0'
                            tcp_acks = '0'
                        '''

                        #Calculate ratio of total syns to total acks for src_ip
                        if new_ip_src != '0':
                            if 'tcp' in jsonObj['_source']['layers']:
                                tcp_total_syns = tcp_meta_dict[ip_src]['totalSyn']
                                tcp_total_acks = tcp_meta_dict[ip_src]['totalAck']
                                if tcp_total_acks != 0:
                                    tcp_syns_to_acks = str(tcp_total_syns/tcp_total_acks)
                                else:
                                    tcp_syns_to_acks = '0'
                            else:
                                tcp_syns_to_acks = '0'
                        else:
                            tcp_syns_to_acks = '0'
                            

                        # Subnet scanning
                        if new_ip_src != '0':
                            if ip_dst in meta_dict and ip_src in meta_dict:
                                if meta_dict[ip_src].get(ip_dst) != None and meta_dict[ip_dst].get(ip_src) != None:
                                    packets_exchanged = str(int(meta_dict[ip_src][ip_dst])+int(meta_dict[ip_dst][ip_src]))
                                    num_small_exchanges = 0
                                    for com in meta_dict[ip_src]:
                                        if com != 'totalSent' and com != 'totalRecieved':
                                            if meta_dict[ip_src][com] <= 32:
                                                num_small_exchanges += 1
                                    num_small_exchanges = str(num_small_exchanges)
                                else:
                                    packets_exchanged = '0'
                                    num_small_exchanges = '0'
                            else:
                                packets_exchanged = '0'
                                num_small_exchanges = '0'
                        else:
                            packets_exchanged = '0'
                            num_small_exchanges = '0'
                        if num_small_exchanges != '0':
                            percentage_small_exhcanges = str(int(num_small_exchanges)/int(packets_exchanged))
                        else:
                            percentage_small_exhcanges = '0'
                        
                        
                        # Fuzz
                        if new_ip_src != '0' and 'http' in jsonObj['_source']['layers'] and tcp_src != '80':
                            if ip_src in http_meta_dict:
                                total_uris = http_meta_dict[ip_src].get('total')
                                unique_uris = http_meta_dict[ip_src].get('unique')
                                unique_uri_ratio = str(unique_uris/total_uris)
                            else:
                                unique_uri_ratio = '0'
                        else:
                            unique_uri_ratio = '0'


                        # Perform checks
                        if ssh_check(tcp_SSH_ratio):
                            bad_flag = True 
                        if port_check(tcp_syns_to_acks):
                            bad_flag = True 
                        if subnet_check(): #TODO
                            bad_flag = True 
                        if fuzz_check(unique_uri_ratio): 
                            bad_flag = True 
                        

                        # ---Data Out---
                        # New line encoded variable (for data seperation)
                        new_line = '\n'
                        new_line_encoded = new_line.encode('utf-8')

                        # Create PreProcessed Data containing recorded data
                        data_string =  new_ip_src           #IP source address
                        data_string += ','
                        data_string += new_ip_dst           #IP destination address
                        # TCP Data
                        data_string += ','
                        data_string += tcp_src              #TCP source port
                        data_string += ','
                        data_string += tcp_dst              #TCP destination port
                        # SSH Bruteforce
                        data_string += ','
                        data_string += tcp_SSH_ratio        #Total number of packets send to tcp port 22 from src_ip
                        # Port scanning(Maybe change from src -> dst to src to all ips )
                        data_string += ','
                        data_string += tcp_syns_to_acks      #Ratio of syns only to acks only recieved by src_ip
                        # Subnet scanning
                        data_string += ','
                        data_string += percentage_small_exhcanges #Ration of exchanged with ips that were less than 32 to all ips it talked to
                        # Fuzz (maybe add uri strings)
                        data_string += ','
                        data_string += unique_uri_ratio             #Ratio of unique uris to all uris sent

                        # Possible addions: packet size, packet time deltas


                        # Convert data string to bytes
                        data_string_encoded = data_string.encode('utf-8')


                        # Add data to bad or good data file
                        if bad_flag:
                            bad_data_out.write(data_string_encoded)
                            bad_data_out.write(new_line_encoded)
                        else:
                            good_data_out.write(data_string_encoded)
                            good_data_out.write(new_line_encoded)

                        #Debug print statements
                        if item_number in good_data_numbers:
                            print('Good Item:', data_string)
                        elif item_number in bad_data_numbers:
                            print('Bad Item: ', data_string)
                        
        # Close files
        good_data_out.close()
        bad_data_out.close()

    except (IOError, KeyError) as e:
        #print('ERROR on item: ', item_number)
        #print(str(e))


        #print('src: ',new_ip_src)
        #print('dst: ',new_ip_dst)
        #print('tcp src port:', tcp_src)
        #print('tcp dst port:',tcp_dst)
        #print('tcp ssh count:',tcp_SSH_count)
        #print('total packets sent: ',total_packets_sent)
        #print('total tcp syns: ',tcp_syns)
        #print('total tcp acks: ',tcp_acks)
        #print('total packets exchanged: ',packets_exchanged)
        #print('number of small exchanges: ',num_small_exchanges)
        #print('number of bad http codes: ',bad_http_codes)
        #print('number of unique https uris: ',unique_http_URIs)
        #print('DONE')
        #print(jsonObj['_source']['layers']['http'])
        pass


# ---Functions to Check conditions go here---
def ssh_check(_tcp_SSH_ratio):
    if float(_tcp_SSH_ratio) >= 0.50:
        return True
    return False

def port_check(_tcp_syns_to_acks):
    if float(_tcp_syns_to_acks) >= 0.80:
        return True
    return False

def subnet_check():
    return False

def fuzz_check(_unique_uri_ratio):
    if float(_unique_uri_ratio) <= 0.50 and float(_unique_uri_ratio) != 0:
        return True
    return False




# ---Collect General Data from file---
# Create a dictonary containing...
def getMetaData(_directory, _file):
    ret_ip_dict = {}
    ret_tcp_dict = {}
    ret_http_dict = {}
    used_uris = []
    try:
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
                    if ret_ip_dict[src].get(dst) == None: 
                        ret_ip_dict[src][dst] = 1
                    else:
                        ret_ip_dict[src][dst] = ret_ip_dict[src].get(dst) + 1
                if ret_ip_dict.get(dst) == None:
                    ret_ip_dict[dst] = {'totalSent': 0, 'totalRecieved': 1}
                    ret_ip_dict[dst][src] = 0
                else:
                    ret_ip_dict[dst]['totalRecieved'] = ret_ip_dict[dst].get('totalRecieved') + 1


                # Recording total number of tcp syns a src sends to each dst, total number of tcp acks a src send to each dst, and total of acks syn a src sent
                # Also recording the total syns and total acks a source recieves
                if 'tcp' in jsonObj['_source']['layers']:
                    # Makes sure src is already in the tcp dict, if not set it up with default data(lots of redundancy here just to make sure)
                    if src in ret_tcp_dict:
                        pass
                    else:
                        #ret_tcp_dict[src]={}
                        ret_tcp_dict[src]={'totalAck': 0, 'totalSyn': 0}
                        ret_tcp_dict[src][dst]={'ack': 0, 'syn': 0}
                    # TCP syn flag but no ack flag
                    if jsonObj['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.syn'] == '1' and jsonObj['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.ack'] == '0':
                        ret_tcp_dict[src]['totalSyn'] = ret_tcp_dict[src].get('totalSyn') + 1
                        if src in ret_tcp_dict:
                            if dst in ret_tcp_dict[src]:
                                ret_tcp_dict[src][dst]['syn'] = ret_tcp_dict[src][dst].get('syn') + 1
                            else:
                                ret_tcp_dict[src][dst]={'ack':0,'syn':1}                           
                        else:
                            ret_tcp_dict[src][dst]['syn'] = 1
                            ret_tcp_dict[src][dst]['ack'] = 0
                            
                    # TCP ack flag but no syn flag
                    if jsonObj['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.syn'] == '0' and jsonObj['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.ack'] == '1':
                        ret_tcp_dict[src]['totalAck'] = ret_tcp_dict[src].get('totalAck') + 1
                        if src in ret_tcp_dict:
                            if dst in ret_tcp_dict[src]:
                                ret_tcp_dict[src][dst]['ack'] = ret_tcp_dict[src][dst].get('ack') + 1
                            else:
                                ret_tcp_dict[src][dst]={'ack':1,'syn':0}                             
                        else:
                            ret_tcp_dict[src][dst]['syn'] = 0
                            ret_tcp_dict[src][dst]['ack'] = 1
                # Recording/Enumerating what tcp port src_ip communicated with on dst_ip
                if 'tcp' in jsonObj['_source']['layers']:
                    dst_port = jsonObj['_source']['layers']['tcp']['tcp.dstport']
                    if ret_tcp_dict.get(src) == None:
                        ret_tcp_dict[src][dst][dst_port] = 1
                    else:
                        if dst in ret_tcp_dict[src]:
                            if ret_tcp_dict[src][dst].get(dst_port) == None:
                                ret_tcp_dict[src][dst][dst_port] = 1
                            else:
                                ret_tcp_dict[src][dst][dst_port] = ret_tcp_dict[src][dst].get(dst_port) + 1
                        else:
                            ret_tcp_dict[src][dst]={'ack':0,'syn':0} 
                            ret_tcp_dict[src][dst][dst_port] = 1

                # 
                if 'http' in jsonObj['_source']['layers']:
                    if 'http.request_number' in jsonObj['_source']['layers']['http']:
                        #Checks if it is a request
                        if jsonObj['_source']['layers']['http']['http.request_number'] == "1":
                            #Creates strings for host, destination, and request uri
                            #host = jsonObj['_source']['layers']['ip']['ip.src']
                            if 'http.request.full_uri' in jsonObj['_source']['layers']['http']:
                                uri = jsonObj['_source']['layers']['http']['http.request.full_uri']
                            else:
                                uri = "None"
                        #Checks if unique ip
                            if src in ret_http_dict:
                                #increments number of unique used uris and total 
                                if uri in used_uris:
                                    ret_http_dict[src]['total'] +=1
                                else:
                                    ret_http_dict[src]['unique'] +=1
                                    ret_http_dict[src]['total'] +=1
                                    used_uris.append(uri)
                            else:
                                ret_http_dict[src] = {"unique": 1, "total" : 1}
                            

    except(IOError, KeyError) as r:
        #print(str(r))
        #print('FAIL in data gathering:')
        #print('src ip:', src)
        #print('dst ip:', dst)
        #print(ret_ip_dict[src])
        #print(ret_tcp_dict)
        #if src in ret_tcp_dict:
        #    print(ret_tcp_dict)
        #if src in ret_http_dict:
        #    print('\n\n',ret_http_dict)
        #if ret_ip_dict is None:
        #    print('ip dict is None')
        #if ret_tcp_dict is None:
        #    print('tcp dict is None')
        #if ret_http_dict is None:
        #    print('http dict is None')
        #print('End of error readout')
        pass
    
    data_handle.close()
    return ret_ip_dict, ret_tcp_dict, ret_http_dict

if __name__ == '__main__':
    preprocess()

    