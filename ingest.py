import sys
import json
import gzip
from pathlib import Path

def proc():
    
    # First argument is the jq file name
    if len(sys.argv) <= 1:
        print ("Missing json file")
        print ('Usage: '+sys.argv[0]+" <json file>")
        sys.exit(-1)

    try:
        counter = 0
        # Open new file (in file + _CONVERTED) to write the new data to
        inName = Path(sys.argv[1]).resolve().stem
        with gzip.open(inName.rsplit('.', 1)[0]+'_CONVERTED.json.gz', 'wb') as f_out:
            # Convert data
            in_handle = gzip.open(sys.argv[1], 'r')
            record = ''
            obj = ''
            for line in in_handle:
                line = line.rstrip()
                line = line.decode('utf-8')
                counter += 1

                # Strip off start and end of json list
                if line == '[':
                    continue
                if line == ']':
                    continue
                # Strip off comma seperating json objects if at end of object
                if line == '  },':
                    line = '  }'
                    line = line.lstrip()
                    record += line

                    #Add complete json object to string array with new line at end
                    recordHolder = json.loads(record)
                    obj += json.dumps(recordHolder)
                    obj += '\n'
                    #print(record)
                    record = ''

                    #Debug break on complete objects
                    if counter > 1000:
                        break
                else:
                    line = line.lstrip()
                    record += line

            #Write complete object to new file
            obj = obj.encode('utf-8')
            f_out.write(obj)

    except (IOError, KeyError) as e:
        print (str(e))
        sys.exit(-1)

if __name__ == '__main__':
    proc()