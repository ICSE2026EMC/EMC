from urllib.request import CacheFTPHandler
import idaapi
import idautils
import idc

for funcAddr in Functions():
    funcName = get_func_name(funcAddr)
    if funcName == 'start':
        print (hex(funcAddr))
for e in Entries():
    print(e)

print(ida_ida.inf_get_main()) 
print(ida_entry.get_entry_qty()) 
print(ida_entry.get_entry_ordinal(652)) 
a = ida_entry.get_entry_ordinal(652)
print(ida_entry.get_entry_name(a), ida_entry.get_entry(a))

entry_num = ida_entry.get_entry_qty()
for index in range(0, entry_num):
    ordinal = ida_entry.get_entry_ordinal(index)
    ida_entry.get_entry_name


# functionlist = []
# entry_num = ida_entry.get_entry_qty()
# for index in range(0, entry_num):
#     ordinal = ida_entry.get_entry_ordinal(index)
#     funcaddr = ida_entry.get_entry_name(ordinal)
#     function_name = ida_entry.get_entry_name(ordinal)
#     if function_name == 'start':
#         entry_point = funcaddr
#         functionlist.append(entry_point)

opcodelist = []
functionlist = []
funcaddr = get_name_ea_simple('start')
functionlist.append(funcaddr)
for function in functionlist:
    insn_addrs = list(idautils.FuncItems(function))
    functionlist.remove(function)   
    for insn in insn_addrs:
        opcode = print_insn_mnem(insn)
        opcodelist.append(opcode)
        if opcode == 'jmp' or opcode == 'call':
            funcaddr = print_operand(insn, 0)  
            funcaddr = get_name_ea_simple(funcaddr)
            functionlist.append(funcaddr)

for opc  in opcodelist:
    print(opc)
