# from urllib.request import CacheFTPHandler
# import idaapi
# import idautils
# import idc
# import time
# # def function_extract(output_file, func, callees):
# #     func_name = get_func_name(func)
# #     print ("Function Name:%s" % (func_name) , file = output_file)
# #     for ref_ea in CodeRefsTo(func, 1):    
# #         caller_name = get_func_name(ref_ea)
# #         callees[caller_name] = callees.get(caller_name, set()) #add the functions from "CodesRefsTo" to a dictionary for extracting CG and CG adjacency Matrix
# #         callees[caller_name].add(func_name)  
# #         print ( "		%s" % (caller_name), file = output_file ) 


from urllib.request import CacheFTPHandler
import idaapi
import idautils
import idc


def controller():
    opcode = []
    basename = ida_nalt.get_root_filename()
    info_filename = "F:\opcodelist_drift\\"+ basename + ".info"    #directory of output
    functions = idautils.Functions()
    for f in functions:
        print(f)
        insn_addrs = list(idautils.FuncItems(f))
        for insn in insn_addrs:
            #print(insn)
            opcode.append(print_insn_mnem(insn))
    print(info_filename)
    with open(info_filename, 'w') as f:
        for opc in opcode:
            f.write(opc)
            f.write('\n') 
      
   
q = None
f = None

ida_auto.auto_wait()


controller()

ida_pro.qexit(0)





