import sys
import json

def proc():
    # First argument is the json file name
    if len(sys.argv) <= 1:
        print ("Missing json file")
        print ('Usage: '+sys.argv[0]+" <jsonfile>")
        sys.exit(-1)

    try:
        with open(sys.argv[1], 'rb') as f:
            line = f.readline().strip();
            for i in range(5000):
                 = f.readline()
            while line:
                obj = json.loads(line)
                if 'tcp' in obj['_source']['layers']:
                    #if obj['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.syn'] == '1':
                    if obj['_source']['layers']['tcp']['tcp.flags'] == '0x00000018':
                        print(obj['_source']['layers']['ip']['ip.src'])
                        print(obj['_source']['layers']['ip']['ip.dst'])
                        #line = f.readline.strip()
    except (IOError, KeyError) as e:
        print (str(e))
        sys.exit(-1)


if __name__ == '__main__':
    proc()