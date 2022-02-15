import sys
import json

def proc():
    
    # First argument is the jq file name
    if len(sys.argv) <= 1:
        print ("Missing jq file")
        print ('Usage: '+sys.argv[0]+" <jq file>")
        sys.exit(-1)
    if len(sys.argv) <= 2:
        print ("Missing command")
        print ('Usage: '+sys.argv[0]+" <syn-ack>")
        sys.exit(-1)
    if len(sys.argv) <= 3:
        print ("Missing src or dst")
        print ('Usage: '+sys.argv[0]+" <src/dst>")
        sys.exit(-1)
    
    # Check for syn-acks being sent.
    if sys.argv[2] == 'syn-ack':
        try:
            with open(sys.argv[1], 'rb') as f:
                line = f.readline().strip();
                for i in range(5000):
                    _ = f.readline()
                while line:
                    obj = json.loads(line)
                    if 'tcp' in obj['_source']['layers']:
                        #if obj['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.syn'] == '1':
                        #    print(obj['_source']['layers']['ip']['ip.src'])
                        if obj['_source']['layers']['tcp']['tcp.flags'] == '0x00000018':
                            if sys.argv[3] == 'src':
                                print(obj['_source']['layers']['ip']['ip.src'])
                            else:
                                print(obj['_source']['layers']['ip']['ip.dst'])
                    line = f.readline().strip()
        except (IOError, KeyError) as e:
            print (str(e))
            sys.exit(-1)


if __name__ == '__main__':
    proc()