import sys
import json
import gzip
from pathlib import Path
import os

# Convert compressed json file into compressed line seperated json file
# Takes location of inital gzipped json file
# Returns line seperated gzipped json file
def proc(directory = './ingestFiles'):
    
    

    try:
        # Look through all files to ingest
        filesTested = 0
        sortedFiles = sorted((f for f in os.listdir(directory) if not f.startswith(".")), key=str.lower)
        for file in sortedFiles:
            # Get current file 
            filename = os.fsdecode(file)
            filesTested += 1

            # Open new file (in file + _CONVERTED) to write the new data to
            in_handle = gzip.open(os.path.join(directory, file), 'r')
            #inName = Path(sys.argv[1]).resolve().stem
            with gzip.open('./preprocesserFiles/'+ file +'_CONVERTED.json.gz', 'w') as f_out:
                counter = 0
                # Convert data
                #in_handle = gzip.open(sys.argv[1], 'r')
                record = ''
                obj = ''

                # Itterate through every line
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
                        record = ''

                    else:
                        line = line.lstrip()
                        record += line

                #Write complete object to new file
                obj = obj.encode('utf-8')
                f_out.write(obj)
            f_out.close()
            
    except (IOError, KeyError) as e:
        print (str(e))
        sys.exit(-1)

if __name__ == '__main__':
    proc()