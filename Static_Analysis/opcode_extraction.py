from urllib.request import CacheFTPHandler
import idaapi
import idautils
import idc



    
        

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
            for head in Heads(current_block.start_ea, current_block.end_ea):    #
                if ida_bytes.is_code(ida_bytes.get_full_flags(head)):      #
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
        pred = list(block.preds())  #
        if not pred and (block.start_ea not in startpoint):
            start_blocks.append(block)

    visited = set() #
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

        
    # all_operations



q = None
f = None

ida_auto.auto_wait()


controller()

ida_pro.qexit(0)
