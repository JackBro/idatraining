import os
import shutil

dest_path = r'C:\Program Files (x86)\IDA 6.9\plugins\Exercise9.py'

if os.path.exists(dest_path):
    print('*** WARNING *** Overwriting plugin "Exercise9.py" is "%s"' % os.path.dirname(dest_path))

shutil.copy('Exercise9.py', r'C:\Program Files (x86)\IDA 6.9\plugins\Exercise9.py')