import os
import subprocess




pefile_dir = '/home/user/zhj/opcodelist_drift_1214/'
pefile_list = os.listdir(pefile_dir)
pe_num = len(pefile_list)
print(pe_num)

# for file in pefile_list:
# 	filename = pefile_dir + file
# 	gexfname = gexf_dir + file + '.gexf'
# 	status,result = subprocess.getstatusoutput('sha256sum %s' % filename)
# 	hashname = gexf_dir + result.split('  ')[0] + '.gexf'
# 	subprocess.getstatusoutput('mv %s %s' % (gexfname, hashname))