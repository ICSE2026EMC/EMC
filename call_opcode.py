from urllib.request import CacheFTPHandler
import idaapi
import idautils
import idc

for funcAddr in Functions():
    funcName = get_func_name(funcAddr)
    if funcName == 'start':#有可能分析不出来start（eg:start导入表的前缀图标不是函数f而是i）
        print (hex(funcAddr))
for e in Entries():#程序的export表中所有的函数信息
    print(e)

print(ida_ida.inf_get_main()) #winmain这种,但有可能分析不出来返回badaddr（例如很多thurRTmain，通过外部导入实现，在text根本追踪不了）
print(ida_entry.get_entry_qty()) #入口点个数
print(ida_entry.get_entry_ordinal(652)) #当入口点很多时无法直接确定start是哪一个
a = ida_entry.get_entry_ordinal(652)
print(ida_entry.get_entry_name(a), ida_entry.get_entry(a)) #ida_entry.get_entry_name(a)可以返回导出表的name信息，因此即使start不是f，不能用前面的get_func_name，但是可以用这种方式获取

entry_num = ida_entry.get_entry_qty()
for index in range(0, entry_num):
    ordinal = ida_entry.get_entry_ordinal(index)
    ida_entry.get_entry_name

'''
先使用ida_ida.inf_get_main()寻找winmain这种入口点，如果返回badaddr找不到，则先获取入口点所有个数，如果有很多个则需要对入口点名称进行分析，确定start的那一个
当然这种情况大概率是入口函数在外部定义，例如分析遇到的vb的ThurRTmain在idata段，因此也通常无法继续追踪下去
'''
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
    functionlist.remove(function)   #删除当前分析的函数以免后面重复
    for insn in insn_addrs:
        opcode = print_insn_mnem(insn)
        opcodelist.append(opcode)
        if opcode == 'jmp' or opcode == 'call':
            funcaddr = print_operand(insn, 0)  #获取call jmp的第一个操作数（唯一）
            funcaddr = get_name_ea_simple(funcaddr)
            functionlist.append(funcaddr)

for opc  in opcodelist:
    print(opc)
