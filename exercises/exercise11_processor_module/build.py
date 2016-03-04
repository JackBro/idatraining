import os
import shutil

dest_path = r'C:\Program Files (x86)\IDA 6.9\procs\Exercise11_processor.py'

if os.path.exists(dest_path):
    print('*** WARNING *** Overwriting plugin "Exercise11_processor.py" is "%s"' % os.path.dirname(dest_path))

shutil.copy('Exercise11_processor.py', r'C:\Program Files (x86)\IDA 6.9\procs\Exercise11_processor.py')
