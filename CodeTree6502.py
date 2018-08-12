import N6502
import Regenerator
import ASMFunction
import MemoryState6502
import FunctionParser6502
import sys
# from collections import namedtuple
# import enum
from graphviz import Digraph
from subFunctionType import eSubFunctionType

if len(sys.argv) < 2:
    print("Code Tree")
    print("---------")
    print("codeTree6502 command_file")
    print("command file format")
    print("regenerator! [optional]<path to regenerator file here>")
    print("prefix! <string> this is prefix for all files made ")
    print("filebase! <path> location to output all files")
    print("vsf! <path> to the vsf file to parse")
    print("entrypoints! hex, hex , hex no $ list of entry points to parse")
    print("forcestops! hex, hex, no $ list of points in the file that are actually stops bne beq combo etc")
    exit(1)

class Params(object):
    def __init__(self):
        self.regenerator = ""
        self.prefix = ""
        self.filebase = ""
        self.vsf = ""
        self.entrypoints = []
        self.forcestops = []

    def parse_file(self,filename):
        with open(filename, "r") as file:
            for line in file.readlines():
                if len(line) > 0:  # make sure not an empty line
                    parts = line.split('!')
                    param = parts[0].strip()
                    if param == "regenerator":
                        self.regenerator = parts[1].strip()
                    elif param == "prefix":
                        self.prefix = parts[1].strip()
                    elif param == "filebase":
                        self.filebase = parts[1].strip()
                    elif param == "vsf":
                        self.vsf = parts[1].strip()
                    elif param == "entrypoints":
                        addresses = parts[1].strip().split(',')
                        for addr in addresses:
                            value = int(addr, 16)
                            self.entrypoints.append(value)
                    elif param == "forcestops":
                        addresses = parts[1].strip().split(',')
                        for addr in addresses:
                            value = int(addr, 16)
                            self.forcestops.append(value)


params = Params()
params.parse_file(sys.argv[1])
# Regenerator.Regenerator_ParseFile("D:\\emulation\\C64\\Tools\\Regenerator17b\\Config\\hunter_moon_actual.vsf.4081430776")
if len(params.regenerator) > 0:
    Regenerator.Regenerator_ParseFile(params.regenerator)

# class eC64_ACCESS(enum.IntEnum):
#    Unknown = 0
#    Execute = 1
#    Read = 4
#    Write = 8


class CodeTree(object):
    def __init__(self):
        # self.C64_RAM_ACCESS = [eC64_ACCESS.Unknown]*(1024*64)
        self.C64_RAM_ACCESS = [MemoryState6502.MemoryState6502() for i in range(1024*64)]
        self.C64_RAM = []
        self.KnownJumpJsrEntryPoints = []  # these keep stock of where you jmp jsr to
        self.FunctionTable = {}  # holds all known ASM function objects
        # self.SubFunctionTable = [] #holds all the branch only objects
        self.NeedToLookAtStack = []  # these keep track of branches that we need to look at
        self.AsmLineList = []  # this is a list of each "line"
        self.AsmLineToCodeDic = {}  # this the code for each "line"
        self.ForcedStops = []  # this is a list of address that are not rts but are ends. known branch etc

    def open_vsf(self, filename):
        with open(filename, "rb") as vsf_file:
            vsf_file.seek(132)  # fix me to actually walk through the headers and find it ;)
            self.C64_RAM = vsf_file.read(1024*64)  # read in the C64 Ram part
    
    def open_prg(self, filename):
        with open(filename, "rb") as prg_file:
            lo = prg_file.read(1)
            hi = prg_file.read(1)
            address = lo[0] + (hi[0] * 256)
            file_data = prg_file.read(1024*64)
            self.C64_RAM = bytearray(1024*64)
            for i in range(0, len(file_data)):
                self.C64_RAM[i+address] = file_data[i]

    def build_tree_starting_at(self, pc):
        # first push through all code and record all jumps, jsrs, branches
        self.NeedToLookAtStack.append(pc)
        found_new = True
        while (len(self.NeedToLookAtStack) > 0) and found_new:
            local_list = list(self.NeedToLookAtStack)  # make a local copy
            del self.NeedToLookAtStack[:]  # clean out the old one
            found_new = False
            # print("Scanning list ",local_list)
            while len(local_list) > 0:
                target = local_list.pop()
                # print("visiting target {:4X}".format(target))
                if self.C64_RAM_ACCESS[target].is_unknown():
                    if target not in self.KnownJumpJsrEntryPoints:
                        self.KnownJumpJsrEntryPoints.append(target)
                    found_new = True
                    self.parse_for_entry_points(target)
        self.KnownJumpJsrEntryPoints.sort()  # sort the entry points
        # print( "all known entry points " , self.KnownJumpJsrEntryPoints)
        # now walk through each known entry point
        for point in self.KnownJumpJsrEntryPoints:
            function_block = self.parse_for_blocks(point)
            self.FunctionTable[function_block.start_address] = function_block

    def parse_for_entry_points(self, pc):
        do = True
        # print("looking for points at {:4X}".format(PC))
        while do:
            opcode = self.C64_RAM[pc]
            if N6502.isOpcodeJSR(opcode) or N6502.isOpcodeJump(opcode):
                target = N6502.calculate16BitAddr(self.C64_RAM[pc + 1], self.C64_RAM[pc + 2])
                self.NeedToLookAtStack.append(target)
                if target not in self.KnownJumpJsrEntryPoints:
                    self.KnownJumpJsrEntryPoints.append(target)
            if N6502.isOpcodeBranch(opcode):
                target = N6502.calculateNewPCFromBranch(pc, self.C64_RAM[pc + 1])
                self.NeedToLookAtStack.append(target)
                if target not in self.KnownJumpJsrEntryPoints:
                    self.KnownJumpJsrEntryPoints.append(target)
                if pc+2 not in self.KnownJumpJsrEntryPoints:
                    self.KnownJumpJsrEntryPoints.append(pc + 2)  # need to add after the branch as well
            if N6502.doesOpcodeReturn(opcode) or N6502.isOpcodeJump(opcode):
                do = False
                # print("stopping at {:4X}".format(PC))
            length = N6502.getOpcodeLength(opcode)
            if pc not in self.AsmLineList:
                line = []
                for i in range(pc, pc+length):
                    self.C64_RAM_ACCESS[i].set_execute()
                    line.append(self.C64_RAM[i])
                self.AsmLineToCodeDic[pc] = line
                self.AsmLineList.append(pc)
            pc = pc + length

    def parse_for_blocks(self, pc):
        do = True
        asm_func = ASMFunction.ASMFunction(pc)
        first_pass = True
        while do:
            opcode = self.C64_RAM[pc]
            # if we find a known entry, break and add the entry as a callee
            if (pc in self.KnownJumpJsrEntryPoints) and (not first_pass):
                asm_func.set_end_address(pc)
                asm_func.add_jumpee(pc)
                do = False
            else:                
                # if we find a branch, break, add the branch target as a callee and the next opcode as callee
                if N6502.isOpcodeBranch(opcode):
                    target = N6502.calculateNewPCFromBranch(pc, self.C64_RAM[pc + 1])
                    asm_func.add_branches(target)
                    asm_func.add_jumpee(target)
                    asm_func.add_jumpee(pc + 2)
                    do = False
                # if we find a jump, break, add the jump as a callee
                if N6502.isOpcodeJump(opcode):
                    target = N6502.calculate16BitAddr(self.C64_RAM[pc + 1], self.C64_RAM[pc + 2])
                    asm_func.add_jumpee(target)
                    do = False
                if N6502.isOpcodeJSR(opcode):
                    target = N6502.calculate16BitAddr(self.C64_RAM[pc + 1], self.C64_RAM[pc + 2])
                    asm_func.add_callee(target)
                # if we find a rts, break
                if N6502.doesOpcodeReturn(opcode) or pc in self.ForcedStops:
                    do = False
                length = N6502.getOpcodeLength(opcode)
                pc = pc + length
                asm_func.set_end_address(pc)
                first_pass = False
        return asm_func

    def double_link_funcs(self):
        for func_table in self.FunctionTable.values():
            for jump in func_table.get_jumps():
                target = self.FunctionTable[jump]
                if target.is_address_outside_func(func_table.start_address):
                    target.add_parent(func_table.start_address)
            for jump in func_table.get_calls():
                target = self.FunctionTable[jump]
                if target.is_address_outside_func(func_table.start_address):
                    target.add_caller(func_table.start_address)

    def move_up_chain_to_find_earlier_single_parent(self, parent_func):
        climb = True  # start the loop
        while climb:
            climb = False  # pretend we don't have one
            if parent_func.should_check_parent_for_merge():  # is this node singular
                parent_address = parent_func.get_parents()[0]  # get the parent address
                parent = self.FunctionTable[parent_address]  # convert it to an object
                if not parent.has_visited():  # have we already determined that the parent is not suitable
                    if parent.get_number_external_jumps() == 1:  # which has to be me
                        parent_func = parent  # move up link
                        climb = True  # look again
        return parent_func

    def remove_addr_from_function_table_and_known_entry_points(self, address):
        self.FunctionTable.pop(address)  # we need to remove it from the function tables
        index = self.KnownJumpJsrEntryPoints.index(address)
        self.KnownJumpJsrEntryPoints.pop(index)  # we also need to remove it as a known entry point

    def mark_all_funcs_unvisited(self):
        for func_table in self.FunctionTable.values():
            func_table.clear_visited()  # make it so all are unvisited
    
    @staticmethod
    def get_object_from_address(address, collection):
        index = collection.index(address)
        return collection[index]

    def merge_funcs(self):
        found = True
        while found:
            self.mark_all_funcs_unvisited()
            merge_candidates = []
            for func_table in self.FunctionTable.values():
                func_table = self.move_up_chain_to_find_earlier_single_parent(func_table)
                if not func_table.has_visited():
                    candidate = [func_table]
                    self.find_merge_single_chain_func(func_table, candidate)
                    if len(candidate) > 1:
                        merge_candidates.append(candidate)
            found = False
            if len(merge_candidates) >= 1:
                found = True
            for candi in merge_candidates:
                # self.mergeListOfFuncThatJumpToEachOther(candi)
                n = self.replace_nodes_with_new_function_from(candi)
                n.set_extra_string("Run")
                n.set_sub_function_type(eSubFunctionType.Run)
        self.find_merge_single_branches()

    def find_merge_single_chain_func(self, asm_function, candidate_list):
        asm_function.mark_visited()
        if asm_function.get_number_external_jumps() == 1:
            target_address = asm_function.get_first_external_jump()
            target = self.FunctionTable[target_address]
            if not target.has_visited():
                if len(target.get_parents()) == 1 and target.has_no_callers():
                    # add test here to see if they follow each other in ram
                    append = True
                    if len(candidate_list) > 0:
                        prev = candidate_list[-1]
                        if prev.get_end_address() != target.get_start_address():
                            append = False
                    if append:
                        candidate_list.append(target)
                        self.find_merge_single_chain_func(target, candidate_list)

    def find_merge_single_branches(self):
        self.mark_all_funcs_unvisited()
        found = True
        external_jumps = []
        external_address = []
        while found:
            found = False
            candidate = False
            del external_jumps[:]
            del external_address[:]
            for function_table in self.FunctionTable.values():
                if function_table.has_visited():
                    continue  # next
                # first we need to find a node that has 2 external jumps
                try:
                    if function_table.get_number_external_jumps() == 2:
                        for address in function_table.get_jumps():
                            if function_table.is_address_outside_func(address):
                                external_jumps.append(self.FunctionTable[address])
                                external_address.append(address)
                                candidate = True
                except:
                    pass
                function_table.mark_visited()
                if candidate:
                    break
            if candidate:
                found = True
                # second we need to make sure one "child" only have 1 jump
                first_single = False
                second_single = False
                if (external_jumps[0].get_number_external_jumps() == 1 and
                   external_jumps[0].has_no_callers() and
                   external_jumps[0].has_single_or_no_parent()):
                    address = external_jumps[0].get_first_external_jump()
                    if address == external_address[1]:
                        first_single = True
                if (external_jumps[1].get_number_external_jumps() == 1 and
                   external_jumps[1].has_no_callers() and
                   external_jumps[1].has_single_or_no_parent()):
                    address = external_jumps[1].get_first_external_jump()
                    if address == external_address[0]:
                        second_single = True
                # third we need to see if one of the children points to the other
                if first_single or second_single:
                    # if so build list of the 3, merge and go again
                    # we need to find all calls by the 2 and add it to the candidate
                    #   add sub function does this for me
                    # tell the children of the opposite of Single that the candidate is now their parent
                    nodes = [function_table]
                    if first_single:
                        nodes.append(external_jumps[0])
                    else:
                        nodes.append(external_jumps[1])
                    n = self.replace_nodes_with_new_function_from(nodes)
                    n.set_extra_string("If")
                    n.set_sub_function_type(eSubFunctionType.IfBlock)
                    # we want to look at this node again to see if it is still a candidate
                    function_table.clear_visited()
    
    def merge_if_else_blocks(self):
        self.mark_all_funcs_unvisited()
        found = True
        external_jumps = []
        external_address = []
        nodes = []
        while found:
            found = False
            candidate = False
            for function_table in self.FunctionTable.values():
                if function_table.has_visited():
                    continue  # next
                del external_jumps[:]
                del external_address[:]
                nodes = ()                
                function_table.mark_visited()
                # first we need to find a node that has 2 external jumps
                if function_table.get_number_external_jumps() == 2:
                    for address in function_table.get_jumps():
                        if function_table.is_address_outside_func(address):
                            external_jumps.append(self.FunctionTable[address])
                            external_address.append(address)
                    first = self.FunctionTable[external_address[0]]
                    second = self.FunctionTable[external_address[1]]
                    if (first.get_number_external_jumps() > 1 or
                       len(first.get_parents()) != 1 or
                       (not first.has_no_callers())):
                        continue
                    if (second.get_number_external_jumps() > 1 or
                       len(second.get_parents()) != 1 or
                       (not second.has_no_callers())):
                        continue
                    if first.get_first_external_jump() == second.get_first_external_jump():
                        candidate = True
                        found = True
                        nodes = (function_table, first, second)
                        break
            if candidate:
                # we need to make sure they are actually inline with each other
                sorted_nodes = [nodes[0]]
                if nodes[1].get_start_address() > sorted_nodes[0].get_start_address():
                    sorted_nodes.append(nodes[1])
                else:
                    sorted_nodes = nodes[1] + sorted_nodes
                if nodes[2].get_start_address() < sorted_nodes[0].get_start_address():
                    sorted_nodes = nodes[2] + sorted_nodes
                elif nodes[2].get_start_address() > sorted_nodes[1].get_start_address():
                    sorted_nodes.append(nodes[2])
                else:
                    sorted_nodes = [nodes[0], nodes[2], nodes[1]]
                if sorted_nodes[0].get_end_address() != sorted_nodes[1].get_start_address():
                    break  # not valid
                if sorted_nodes[1].get_end_address() != sorted_nodes[2].get_start_address():
                        break  # not valid
                n = self.replace_nodes_with_new_function_from(nodes)
                n.set_sub_function_type(eSubFunctionType.IfElseBlock)
                n.set_extra_string("IfElse")
                # its a new one, so not visited
                # func.clearVisited() # we want to look at this node again to see if it is still a candidate

    def find_merge_direct_loops(self):
        self.mark_all_funcs_unvisited()
        found = True
        while found:
            found = False
            for function_table in self.FunctionTable.values():
                if function_table.has_visited():
                    continue  # next
                function_table.mark_visited()
                if function_table.has_single_child():
                    if function_table.get_number_external_jumps() > 0:
                        child = self.FunctionTable[function_table.get_first_external_jump()]  # only one so has to be it
                        if function_table.get_start_address() < child.get_start_address():
                            if function_table.get_start_address() in child.get_jumps():  # am I parent of it
                                if child.has_single_or_no_parent():  # am I its only child + something else
                                    n = self.replace_nodes_with_new_function_from((function_table, child))
                                    n.set_extra_string("Loop")
                                    n.set_sub_function_type(eSubFunctionType.Loop)
                                    found = True
                                    break
    
    def find_functions_group(self):
        self.mark_all_funcs_unvisited()
        found = True
        while found:
            found = False
            candidate = False
            for function_table in self.FunctionTable.values():
                if function_table.has_visited():
                    continue  # next
                function_table.mark_visited()
                if function_table.is_function_head():
                    all_children = []
                    function_table.append_all_children(all_children, self)
                    if len(all_children) < 2:  # 0 or 1 then nope
                        continue
                    found = True
                    candidate = True
                    for child in all_children:
                        if child != function_table:
                            if not child.has_no_callers():
                                candidate = False
                                break  # not a valid candidate
                            for parent in child.get_parents():
                                pf = self.FunctionTable[parent]
                                if pf not in all_children:
                                    candidate = False  # not a valid candidate
                                    break
                    if candidate:
                        break

            if candidate:
                print("found func")
                o = "["
                for node in all_children:
                    o += "{:4X}".format(node.get_start_address())
                print(o+"]")
                nf = self.replace_nodes_with_new_function_from(all_children)
                nf.set_extra_string(" FUNC")
                nf.set_sub_function_type(eSubFunctionType.FuncGroup)
                nf.mark_visited()

    def replace_nodes_with_new_function_from(self, nodes):
        new_func_address = nodes[0].get_start_address()
        new_function = ASMFunction.ASMFunction(new_func_address)
        for parent in nodes[0].get_parents():
            new_function.add_parent(parent)  # as the address is the same the parents don't need to update the child
        nodes_address = []
        print("merging")
        for node in nodes:
            nodes_address.append(node.get_start_address())
            print(node.make_a_summery())
            if node.get_end_address() > new_function.get_end_address():
                new_function.set_end_address(node.get_end_address())
        for node in nodes:
            for call in node.get_calls():
                # newFunc.addCallee(call) done by add sub function
                if call != new_func_address:
                    called = self.FunctionTable[call]
                    called.update_caller_to(node.get_start_address(), new_func_address)
            for jump in node.get_jumps():
                if jump < new_func_address or jump >= new_function.get_end_address():  # if it is external, update it
                    new_function.add_jumpee(jump)
                    jumped = self.FunctionTable[jump]
                    jumped.update_parent_to(node.get_start_address(), new_func_address)
            for called in node.get_callers():
                new_function.add_caller(called)
            new_function.add_sub_function(node)  # Change me to keep add the sub group
            new_function.set_extra_string(node.get_extra_string())
        for address in nodes_address:
            self.remove_addr_from_function_table_and_known_entry_points(address)
        new_function.remove_all_internal_parents()
        self.FunctionTable[new_func_address] = new_function
        self.KnownJumpJsrEntryPoints.append(new_func_address)
        print("merged")
        print(new_function.make_a_summery())
        return new_function

    def build_tree_graph(self, graph_file_name):
        dot = Digraph(name="6502 Code")
        jsr_counters = {}
        complete_names = {}
        for node in self.KnownJumpJsrEntryPoints:
            original = Regenerator.Regenerator_getLabelForAddr(node)  # "{:4X}".format(node) #
            extra_string = self.FunctionTable[node].get_extra_string()
            filename = ""
            if len(extra_string.strip()):
                item_counter = 0
                formatted_extra = ""
                for part in extra_string.split("\n"):
                    formatted_extra += part
                    item_counter += 1
                    if item_counter == 4:
                        item_counter = 0
                        formatted_extra += "\n"
                    else:
                        formatted_extra += " "
                filename = game_prefix + "_graph_func_{:4X}.gv.svg".format(func.get_start_address())
                node_name = original + "\n" + formatted_extra
                node_type = 'box'
            else:
                node_name = original
                node_type = 'circle'
            if len(filename):
                dot.node(node_name, shape=node_type, URL=filename)
            else:
                dot.node(node_name, shape=node_type)
            complete_names[original] = node_name
        for function_name in self.FunctionTable.values():
            original = Regenerator.Regenerator_getLabelForAddr(function_name.get_start_address())
            # node_name = original + " " + function_name.getExtraString()
            node_name = complete_names[original]
            for callee in function_name.get_calls():
                callee_function = self.FunctionTable[callee]
                if len(callee_function.get_callers()) > 2:
                    call_str_original = Regenerator.Regenerator_getLabelForAddr(callee)
                    call_str = call_str_original  # + " " + self.FunctionTable[callee].getExtraString()
                    jsr_count = 0
                    if call_str in jsr_counters:
                        jsr_count = jsr_counters[call_str]
                        jsr_counters[call_str] = jsr_count + 1
                    else:
                        jsr_counters[call_str] = 1
                    call_str = call_str + "[" + str(jsr_count) + "]"
                    dot.node(call_str, shape='diamond')
                else:
                    call_str_original = Regenerator.Regenerator_getLabelForAddr(callee)
                    call_str = complete_names[call_str_original]
                # dot.edge(node_name, call_str, constraint='false', color='red')
                # dot.edge(completeNames[node_name], completeNames[call_str], color='red')
                dot.edge(node_name, call_str, color='red')
            for callee in function_name.get_jumps():
                call_str_original = Regenerator.Regenerator_getLabelForAddr(callee)
                # call_str = call_str_original + " " + self.FunctionTable[callee].getExtraString()
                call_str = complete_names[call_str_original]
                # dot.edge(completeNames[node_name], completeNames[call_str])
                dot.edge(node_name, call_str)
        # print(dot.source)
        dot.format = 'svg'
        dot.render(graph_file_name, view=False)
    
    def make_sub_graph(self, function_object):
        all_calls_address = []
        all_funcs = []
        all_function_address = []
        sub_graph = Digraph("cluster_" + function_object.get_extra_string(),
                            graph_attr={"label": function_object.get_extra_string()})
        sub_graph.format = 'svg'
        function_object.mark_visited()
        for f in function_object.get_sub_functions():
            if not f.has_visited() and f.get_sub_function_type() != eSubFunctionType.Unknown:
                sub_graph.subgraph(self.make_sub_graph(f))
            else:
                all_function_address.append(f.get_start_address())
                all_funcs.append(f)
                all_calls_address.extend(f.get_calls())
        for n in all_function_address:
            # string = "{:4X}".format(n)
            string = Regenerator.Regenerator_getLabelForAddr(n)
            sub_graph.node(string)
        for address in all_calls_address:
            # string = "{:4X}".format(address)
            string = Regenerator.Regenerator_getLabelForAddr(address)
            sub_graph.node(string, shape='cds')
        for f in all_funcs:
            for jump in f.get_jumps():
                # stringA = "{:4X}".format(f.getStartAddr())
                string_a = Regenerator.Regenerator_getLabelForAddr(f.get_start_address())
                # stringB = "{:4X}".format(jump)
                string_b = Regenerator.Regenerator_getLabelForAddr(jump)
                sub_graph.edge(string_a, string_b)
            for call in f.get_calls():
                # stringA = "{:4X}".format(f.getStartAddr())
                string_a = Regenerator.Regenerator_getLabelForAddr(f.get_start_address())
                # stringB = "{:4X}".format(call)
                string_b = Regenerator.Regenerator_getLabelForAddr(call)
                sub_graph.edge(string_a, string_b, color='red')
        return sub_graph

    def build_access_svg(self, filename):
        with open(filename, "w") as svg:
            svg.write('<svg version="1.1" baseProfile="full" width="2560" height="2560"'
                      ' xmlns="http://www.w3.org/2000/svg">')
            index_x = 0
            index_y = 0
            scale = 10
            border = 1
            colour_to_mode = ("gray", "darkblue", "green", "yellow", "red", "lightblue")  # fix me for all the flags
            for mode in self.C64_RAM_ACCESS:
                start_x = (index_x * scale) + border
                start_y = (index_y * scale) + border
                end_x = ((index_x+1) * scale) - border
                end_y = ((index_y+1) * scale) - border
                colour_index = 0
                if mode.does_r():
                    colour_index = 2
                    if mode.does_w():
                        colour_index = 3
                elif mode.does_w():
                    colour_index = 4
                if mode.is_vector():
                    colour_index = 5
                if mode.does_exectue():
                    colour_index = 1
                svg.write('<rect x="{:d}" y="{:d}" width="{:d}" height="{:d}" fill="{:s}"/>'
                          .format(start_x, start_y, end_x-start_x, end_y-start_y, colour_to_mode[colour_index]))
                index_x += 1
                if index_x >= 256:
                    index_x = 0
                    index_y += 1
            svg.write("</svg>")

    def recurse_tree(self, parent, tab_index):
        out = ""
        for v in range(0, tab_index):
            out = out + '\t'
        out = out + parent.get_sub_function_type().value
        print(out)
        for sub in parent.get_sub_functions():
            self.recurse_tree(sub, tab_index + 1)

    def recurse_tree_sub_funcs(self, parent, tab_index):
        indent = ""
        for v in range(0, tab_index):
            indent = indent + ' '
        out = indent + parent.make_a_summery()
        print(out)
        parent.mark_visited()
        print(indent+"subs ") 
        for sub in parent.get_sub_functions():
            if not sub.has_visited():
                self.recurse_tree_sub_funcs(sub, tab_index + 1)
        print(indent+"jump ")
        for sub in parent.get_jumps():
            if sub in self.FunctionTable:
                sub_function = self.FunctionTable[sub]
                if not sub_function.has_visited():
                    self.recurse_tree_sub_funcs(sub_function, tab_index + 1)

# game_prefix = "HM"
# fileBase = "D:\\PathStuff\\" + game_prefix
# fileBase = "D:\\GitHub\\CodeTreeTests\\simpleXloop"

game_prefix = params.prefix
fileBase = params.filebase + params.prefix

tree = CodeTree()
# tree.open_vsf("D:\\GitHub\\Thalamus\\HuntersMoon\\hunter_moon_actual.vsf")
# entryPoints = [0x190c, 0x13BF, 0x13C2]
# tree.ForcedStops = [0x0fc8]
tree.open_vsf(params.vsf)
entryPoints = params.entrypoints
tree.ForcedStops = params.forcestops

for entry in entryPoints:
    tree.build_tree_starting_at(entry)

tree.double_link_funcs()
oldCount = len(tree.KnownJumpJsrEntryPoints)
loop = 1
while True:
    print("Gen - "+str(loop))
    print("find Loop")
    tree.find_merge_direct_loops()
    print("fine Ifs")
    tree.find_merge_single_branches()
    print("find IFElse")
    tree.merge_if_else_blocks()
    print("find runs")
    tree.merge_funcs()
    if len(tree.KnownJumpJsrEntryPoints) == oldCount:
        break  # we found nothing new
    oldCount = len(tree.KnownJumpJsrEntryPoints)
    loop = loop + 1

tree.find_functions_group()

tree.AsmLineList.sort()

for func in tree.FunctionTable.values():
    FunctionParser6502.parse_function(tree.C64_RAM_ACCESS, tree.AsmLineToCodeDic, tree.AsmLineList, func)

# start = tree.FunctionTable[0x9067]
# tree.recurseTree(start,0)

tree.build_access_svg(fileBase + "exec.svg")
tree.build_tree_graph(fileBase + ".gv")

# tree.markAllFuncsUnvisited()
# tree.recurseTreeSubFuncs(tree.FunctionTable[0x35b6],0)

tree.mark_all_funcs_unvisited()
for func in tree.FunctionTable.values():
    if (func.get_sub_function_type() == eSubFunctionType.FuncGroup or
       func.get_sub_function_type() == eSubFunctionType.Run):
        name = "graph_func_{:4X}".format(func.get_start_address())
        graph = tree.make_sub_graph(func)
        graph.render(fileBase+"_"+name+".gv", view=False)

# print(Regenerator.getRegenerator().codeStart)
