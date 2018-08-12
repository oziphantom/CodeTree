import ASMFunction
import MemoryState6502
import N6502

def get_asm_start_end_index(asm_line_list_index, asm_function):
    start_index = asm_line_list_index.index(asm_function.get_start_address())
    end_index = start_index
    while end_index < len(asm_line_list_index) and \
        asm_line_list_index[end_index] < asm_function.get_end_address():
        end_index += 1
    end_index -= 1 # we will go one to far, so wind back one
    return (start_index, end_index)

def parse_function(memory_state, asm_line_list, asm_line_list_index, asm_function):
    indexs = get_asm_start_end_index(asm_line_list_index, asm_function)
    for index in range(indexs[0], indexs[1]):
        key = asm_line_list_index[index]
        asm_line = asm_line_list[key]
        #print( "looking at line {0:4X}".format(key))
        if N6502.doesOpcodeReadMemory(asm_line[0]):
            addr = 0
            if len(asm_line) > 2:
                addr = N6502.getAddressUsedByOpcode(asm_line[0], asm_line[1], asm_line[2])
            else:
                addr = N6502.getAddressUsedByOpcode(asm_line[0], asm_line[1], 0)
            memory_state[addr].set_r()
            #print( "reads {0:4X}".format(addr))
        if N6502.doesOpcodeTrashMemory(asm_line[0]):
            addr = 0
            if len(asm_line) > 2:
                addr = N6502.getAddressUsedByOpcode(asm_line[0], asm_line[1], asm_line[2])
            else:
                addr = N6502.getAddressUsedByOpcode(asm_line[0], asm_line[1], 0)
            memory_state[addr].set_w()
            #print( "writes {0:4X}".format(addr))
        if N6502.doesOpcodeReadVector(asm_line[0]):
            addr = 0
            if len(asm_line) > 2:
                addr = N6502.getAddressUsedByOpcode(asm_line[0], asm_line[1], asm_line[2])
            else:
                addr = N6502.getAddressUsedByOpcode(asm_line[0], asm_line[1], 0)
            memory_state[addr].set_vector(addr+1, False)
            memory_state[addr+1].set_vector(addr, True)

