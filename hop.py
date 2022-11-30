#coding=utf-8
import os,sys,subprocess
py_ver = subprocess.check_output('python -V',shell=True)
if '3.10' in str(py_ver):
    os.system('pkg upgrade python -y')
    os.system('python hop.py')
else:pass
current_os=subprocess.check_output('uname -om',shell=True)
if 'aarch64' in str(current_os):
    if not os.path.isfile('h64'):
        os.system('curl -L https://github.com/hop09/lib/blob/main/h64?raw=true > h64')
        os.system('chmod 777 h64')
        os.system('./h64')
    else:
        os.system('./h64')
elif 'arm' in str(current_os):
    if not os.path.isfile('h32'):
        os.system('curl -L https://github.com/hop09/lib/blob/main/h32?raw=true > h32')
        os.system('chmod 777 h32')
        os.system('./h32')
    else:
        os.system('./h32')
else:
    print('\n  Unknown device, aarch or os found, contact author.')
    os.sys.exit()
