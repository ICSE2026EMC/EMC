import os
import csv


# hashname = {}
# with open('/work/MalwareBazaar_Labels.csv','r') as f:
# 	for line in f:
# 		hashname.setdefault(line.split(',')[0],line.split(',')[1])
# print(hashname['0a7e7f12d79130da067fd39ede7ff4dc3dc6665d88f5278745074d77132312bf'])

# folder_path = "/work/opcodelist/"

# output_path = "/work/zhj/output_file.txt"

# with open(output_path, "w") as output_file:
#     for file_name in os.listdir(folder_path):
#         if os.path.isfile(os.path.join(folder_path, file_name)):
#             with open(os.path.join(folder_path, file_name), "r") as input_file:
#                 file_name = file_name.split('.')[0]
#                 output_file.write(file_name + ' ')
#                 file_contents = " ".join(line.strip() for line in input_file)
#                 output_file.write(file_contents)
#                 if hashname[file_name] == 'Gozi': 
#                         label = '0'
#                 elif hashname[file_name] == 'GuLoader': 
#                         label = '1'
#                 elif hashname[file_name] == 'Heodo': 
#                         label = '2'
#                 elif hashname[file_name] == 'IcedID': 
#                         label = '3'
#                 elif hashname[file_name] == 'njrat': 
#                         label = '4'
#                 else:
#                         hashname[file_name] == 'Trickbot'
#                         label = '5'
#                 output_file.write(' ' + label)
#                 output_file.write('\n')



# import subprocess
# path = '/work/opcodelist_drift2/'
# hashname = {}
# with open('/work/MalwareDrift_Labels.csv','r') as f:
# 	for line in f:
# 		hashname.setdefault(line.split(',')[0],line.split(',')[3])

# pefile_dir = '/work/malwareexe/'
# pefile_list = os.listdir(pefile_dir)
# pe_num = len(pefile_list)
# print(pe_num)

# for file_name in os.listdir(path):
#     pename = pefile_dir + file_name.split('.')[0]
#     status,result = subprocess.getstatusoutput('sha256sum %s' % pename)
#     hash_name = result.split('  ')[0]
#     if hashname[hash_name] == 'pre-drift\n':
#         subprocess.getstatusoutput('mv %s %s' % (path + file_name, '/work/opcodelist_drift/pre/' + hash_name))

#     if hashname[hash_name] == 'post-drift\n':
#         subprocess.getstatusoutput('mv %s %s' % (path + file_name, '/work/opcodelist_drift/post/' + hash_name))
        



hashname = {}
with open('MalwareDrift_Labels.csv','r') as f:
	for line in f:
		hashname.setdefault(line.split(',')[0],line.split(',')[1])

folder_path = "/work/opcodelist_drift/post"	# The path of the output of file ida_opcode.py
#folder_path = "/work/opcodelist_drift/post"
output_path = "/work/output_file_post.txt"	# The path of the output results
#output_path = "/work/zhj/output_file_post.txt"

with open(output_path, "w") as output_file:
    for file_name in os.listdir(folder_path):
        if os.path.isfile(os.path.join(folder_path, file_name)):
            with open(os.path.join(folder_path, file_name), "r") as input_file:
                file_name = file_name.split('.')[0]
                output_file.write(file_name + ' ')
                file_contents = " ".join(line.strip() for line in input_file)
                output_file.write(file_contents)
                if hashname[file_name] == 'bifrose': 
                        label = '0'
                elif hashname[file_name] == 'ceeinject': 
                        label = '1'
                elif hashname[file_name] == 'obfuscator': 
                        label = '2'
                elif hashname[file_name] == 'vbinject': 
                        label = '3'
                elif hashname[file_name] == 'vobfus': 
                        label = '4'
                elif hashname[file_name] == 'winwebsec': 
                        label = '5'
                else:
                        hashname[file_name] == 'zegost'
                        label = '6'
                output_file.write(' ' + label)
                output_file.write('\n')





