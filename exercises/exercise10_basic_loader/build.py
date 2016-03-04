import os
import shutil

dest_path = r'C:\Program Files (x86)\IDA 6.9\loaders\Exercise10_ldr.py'

if os.path.exists(dest_path):
    print('*** WARNING *** Overwriting loader "Exercise10_ldr.py" is "%s"' % os.path.dirname(dest_path))

shutil.copy('Exercise10_ldr.py', r'C:\Program Files (x86)\IDA 6.9\loaders\Exercise10_ldr.py')
