from urllib.request import CacheFTPHandler
import idaapi
import idautils
import idc



'''
根据所有的跳转和调用指令的操作数判断是否超出了当前函数的有效边界,如果有则是调用；
根据所有函数地址(Functions()+import/export表)的代码/数据交叉引用得到程序整体的函数调用图,进行查漏补全,
没有被start链上调用的按顺序分析放到最终结果的最后杂项。

在处理调用关系时:1.考虑可以溯源的间接调用,利用参数寻找到原位置后判断是否是函数名入口(text、idata)
2.如果不是考虑是否是数据,如果是数据则可能是间接调用中的外部动态调用,将此类情况用同意标识符处理
3.代码存根stub处理
'''

'''
直接对全局地址做cfg:1.从start开始找后续,获取opc
2.从有后继无前继、无后继无前继按顺序获取opc,此处注意stub的库函数会出现在text段，因此stub也会被全部当成无前继基本块处理！
3.补充杂项(必要性存疑)
在处理循环时,只需要判断当前后续节点的地址是否属于一个已经处理过的地址(注意不是地址的所在函数)
ps:flowchart不对call的调用进行后续分析,包括call ds:api,call sub,call eax,jmp ds:_adj_fdiv_m16i...
因此要对call指令的操作数进行分析，同时也是为了分析间接调用指令，通过对操作数的类型进行判断可以识别是否是寄存器等间接调用)；
此外还要考虑除了call指令之外的调用指令例如jmp，syscall，invoke等等。
此外例如:VirusShare_6b0c43d809e3ebb3c29f9848169448fa。是一个C#代码的中间语言表示形式（IL）。IL是在编译C#代码后生成的中间语言，而不是直接运行的代码。在实际运行时，这些IL指令会被JIT编译器（Just-In-Time Compiler）转换为特定平台的本机机器码。
其中包含有定义的类和虚函数，普通的函数调用分析无法分析出这种潜在的调用因此无法通过交叉引用分析获取，
注意stub的库函数会出现在text段，因此需要剔除（stub一般都会被call调用，但基本块识别时无法进入call，因此stub会被当成无前继）
'''
'''
通过对functions左侧已知函数进行trunk和lib判断，1.可以去掉库函数内嵌copy实现在代码段中的那些基本块分析2.stub等跳转存根的基本块冗余分析
通过import表解析可以补全左侧识别不全的函数调用（因为已知函数一般是函数体在text段的）；当然也可以通过分析call指令的操作数类型是否是o_mem(直接内存引用，call ds:libfuncs)
注意这两者的关系：libfunc如果有stub则已知函数里会出现stub，call调用stub时操作数类型为o_near（7），stub中通过jmp o_mem实现跳转；如果没有stub则是直接jmp o_mem跳转
因此先通过搜索import表记录全部libfunc被调用的地址，当执行到该地址的时候直接将函数名加入（注意此时由于是ds地址调用所以是dataref，因此要么对导入表做dataref，要么分析call时检测到时o_mem，判断地址是否在idata段外，然后直接获取函数名）

get_operand_value(ea, n)    官网定义
jmp  sub_401E00    7            addr    #一般是jmp thunk；thunk函数中jmp到真正的sub函数，而thunk函数本身401E00是一个数据引用，由data段的offset sub401E00保存，然后通过mov eax offset sub_4010E00； call eax调用
call sub_xxx       7            addr
call stub          7            addr
call ds:libfunc 2               addr
call dword ptr [eax]  3         0x0
call dword ptr [ecx]  3         0x1
call dword ptr [eax+0Ch]  4     0xc
call dword ptr [ecx+8]    4     0x8
call    eax       1             0x0
call    ebx       1             0x3
call    ebp       1             0x5
call _memcpy_s(定义在text左侧已知)7   addr
'''

'''
1.先进行flowchart，得到整体cfg
2.使用交叉引用将函数调用关系进行填补构建（因为flowchart不会对调用关系进行构建，只是构建单独的block）
3.查找calljmpinvoke等调用指令，对操作数进行类型分析，识别间接调用
'''



# opcode = []
# functions = idautils.Functions() #返回值空
# print('functions')
# for f in functions:
#     print(hex(f))
#     opcode.append('-------------------------------')
#     opcode.append(get_func_name(f))
#     insn_addrs = list(idautils.FuncItems(f))
#     for insn in insn_addrs:
#         opcode.append(print_insn_mnem(insn))


# insn_addr = idautils.FuncItems(4199261)  #只能对函数用不能对loc代码块用，返回值空
# for ins in insn_addr:
#     print(print_insn_mnem(ins))

        


#     #根据所有的跳转和调用指令的操作数判断是否超出了当前函数的有效边界，如果有则是调用；根绝所有函数地址（Functions()+import/export表）的代码/数据交叉引用得到程序整体的函数调用图，进行查漏补全，没有被start链上调用的按顺序分析放到最终结果的最后杂项。 
# for f in Functions(start=4198400, end=4199423):  #只能对左侧显示的函数用不能对loc代码块用，返回值空
#     print(hex(f))
    
# addr = Chunks(4199361) #只能对函数用，获取首尾地址，返回值空
# for a in addr:
#     print(a)
# print('name')
# print(hex(get_name_ea_simple('loc_40135D')))#返回值0xffffffffff
# print('getfunc') 
# print(idaapi.get_func(int('40128D',16))) #只能对函数用,返回ida_funcs.func_t类使用.start_ea获取函数首地址,返回值none
# print('getfuncattr ')
# print(hex(get_func_attr(4199261,FUNCATTR_START))) #只能对函数用，返回值0xffffffffffff
# print(hex(idc.next_head(0x4013A5)))#返回值 0xfffffffff
# print(hex(ida_ida.inf_get_min_ea()),hex(ida_ida.inf_get_max_ea()))


# def cls_main():   # 444a65 - 444a66 [1260]: succs: 444a66 - 444a84 [1261]: preds:444a28 - 444a5c [1258]:

#     f = idaapi.FlowChart(bounds=(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()))
#     for block in f:
#         #print("%x - %x [%d]:" % (block.start_ea, block.end_ea, block.id))

#         for succ_block in block.succs(): # 获取后继节点
#             print("  succs: %x - %x [%d]:" % (succ_block.start_ea, succ_block.end_ea, succ_block.id))
                
#         for pred_block in block.preds(): # 获取前驱节点
#             print("  preds:%x - %x [%d]:" % (pred_block.start_ea, pred_block.end_ea, pred_block.id))
    
        

def dfs_traversal(start_block, visited=None, operations=None):
    if visited is None:
        visited = set()
    if operations is None:
        operations = []
    stack = [start_block]
    while stack:
        current_block = stack.pop()
        print(hex(current_block.start_ea))
        if current_block.start_ea not in visited:
            visited.add(current_block.start_ea)
            for head in Heads(current_block.start_ea, current_block.end_ea):    #获取的是数据/代码的地址
                if ida_bytes.is_code(ida_bytes.get_full_flags(head)):      #节约开销，由于是基本块分析过来的因此不可能是数据
                    mnem = print_insn_mnem(head)
                    operations.append(mnem)
                # if mnem == 'call':
                #     print()

            for succ_block in current_block.succs():
                if succ_block.start_ea not in visited:
                    stack.append(succ_block)

    return operations

def controller():
    basename = ida_nalt.get_root_filename()
    info_filename = "F:\opcodelist_drift_1214\\"+ basename + ".info"

    entry_list = Entries() #return: List of tuples (index, ordinal, ea, name)
    startpoint = []     
    for entry_point in entry_list:
        startpoint.append (entry_point[2])
        print('start at ' + hex(entry_point[2]))


    f = idaapi.FlowChart(bounds=(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()))
    start_blocks = []
    for block in f:
        if block.start_ea in startpoint:
            start_blocks.append(block)
    for block in f:
        pred = list(block.preds())  #pred返回的是迭代器对象，因此无论有无内容都是逻辑true
        if not pred and (block.start_ea not in startpoint):
            start_blocks.append(block)

    visited = set() #不同入口点遍历到相同路径则跳过
    all_operations = []
    for start_block in start_blocks:
        operations = dfs_traversal(start_block, visited=visited)
        all_operations.extend(operations)
    # for opc in all_operations:
    #     print(opc)
    print(info_filename)
    with open(info_filename, 'w') as f:
        for opc in all_operations:
            f.write(opc)
            f.write('\n')

        
    # all_operations 中包含了每个块的操作序列，按照深度优先的顺序遍历所有节点



q = None
f = None

ida_auto.auto_wait()


controller()

ida_pro.qexit(0)
