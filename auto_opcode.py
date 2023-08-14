import os 
import subprocess
import sys
from get_call_graph import *
import time
ida_path = "D:\IDAPro\ida64.exe"
work_dir = os.path.abspath('.')
#pefile_dir = os.path.join(work_dir, 'pefile')
pefile_dir = 'F:\MalwareDrift\malwareexe'   #directory of malware binary files 
script_path = os.path.join(work_dir, 'ida_opcode.py')

pefile_list = os.listdir(pefile_dir)
pefile_num = len(pefile_list)
print(pefile_num)
for file in pefile_list:
    #cmd_str = ./idaq64 -Lida.log -c -A -Sanalysis.py pefile
    # cmd_cd = 'cd /mnt2/lzq/components/IDA_Pro_v6.4'
    # sys.stdout.flush()
    # subprocess.call(cmd_cd, shell=True)
    #if file.endswith('dll') or file.endswith('exe'):
        # p = subprocess.Popen((cmd_str))
    cmd_ida = '{} -Lida.log -c -A -S{} {}'.format(ida_path,script_path, os.path.join(pefile_dir, file))
        #sys.stdout.flush()
 #   tic = time.time()
    subprocess.call(cmd_ida, shell=True)

#    tic = time.time() - tic
 #   with open('D:\\IDAPro\\workspace\\e.txt', 'w+') as f:
  #      f.write(str(tic))
    #print(cmd_ida)
        #p.wait()
    #生成gexf文件
    #use_ida_to_get_call_graph('D:\IDAPro\workspace\output\\')
    #print(111)
