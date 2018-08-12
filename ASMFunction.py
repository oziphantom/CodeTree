from subFunctionType import eSubFunctionType


class ASMFunction(object):
    def __init__(self, start_address):
        self.start_address = start_address
        self.end_address = start_address
        self.calls = []  # what do I jsr too
        self.jumps = []  # what do I jump to, my children
        self.callers = []  # who jsrs to me
        self.parents = []  # who jumps to me
        self.exitPoints = [] 
        self.branches = []  # what jumps above are actually branches
        self.subFuncs = []  # things that have been merged into me
        self.subFunctionType = eSubFunctionType.Unknown
        self.visit = False
        self.extraString = ""

    def add_callee(self, call_address):
        if call_address not in self.calls:
            self.calls.append(call_address)

    def add_caller(self, caller_address):
        if caller_address not in self.callers:
            self.callers.append(caller_address)

    def add_jumpee(self, jump_address):
        if jump_address not in self.jumps:
            self.jumps.append(jump_address)

    def add_parent(self, parent_address):
        if parent_address not in self.parents:
            self.parents.append(parent_address)

    def add_sub_function(self, func):
        self.subFuncs.append(func)
        # self.calls = self.calls + func.getCalls()
        for address in func.get_calls():
            self.add_callee(address)
        self.branches = self.branches + func.get_branches()

    def get_sub_functions(self):
        return self.subFuncs

    def set_end_address(self, end_address):
        self.end_address = end_address

    def add_exit_point(self, address):
        self.exitPoints.append(address)

    def add_branches(self, address):
        self.branches.append(address)

    def get_branches(self):
        return self.branches

    def get_calls(self):
        return self.calls

    def get_callers(self):
        return self.callers

    def get_jumps(self):
        return self.jumps

    def get_parents(self):
        return self.parents

    def remove_jump(self, address):
        old_index = self.jumps.index(address)
        self.jumps.pop(old_index)

    def get_number_external_jumps(self):
        count = 0
        for jump in self.get_jumps():
            if (jump < self.get_start_address()) or (jump >= self.get_end_address()):
                count += 1
        return count

    def get_first_external_jump(self):
        for jump in self.get_jumps():
            if (jump < self.get_start_address()) or (jump >= self.get_end_address()):
                return jump
        print("Error")
        return 0

    def does_address_point_to_exit(self, address):
        if address in self.exitPoints:
            return True
        return False

    def is_address_outside_func(self, address):
        if self.end_address == 0:
            print("ERROR - address check on incomplete func")
            return False
        else:
            if (address < self.start_address) or (address >= self.end_address):
                return True
            return False

    def get_start_address(self):
        return self.start_address

    def get_end_address(self):
        return self.end_address

    def mark_visited(self):
        self.visit = True

    def has_visited(self):
        return self.visit

    def clear_visited(self):
        self.visit = False
        for sub in self.subFuncs:
            sub.clear_visited()

    def make_a_summery(self):
        s = "Function starts at {:X} and ends at {:X} and calls [".format(self.start_address, self.end_address)
        for a in self.calls:
            s += "{:4X} ".format(a)
        s += "] jumps ["
        for a in self.jumps:
            s += "{:4X} ".format(a)
        s += "] callers ["
        for a in self.callers:
            s += "{:4X} ".format(a)
        s += "] parents ["
        for a in self.parents:
            s += "{:4X} ".format(a)
        s += "] subs ["
        for a in self.subFuncs:
            s += "{:4X} ".format(a.get_start_address())
        s += "] function type " + str(self.subFunctionType.value)
        return s

    def should_check_parent_for_merge(self):
        if len(self.parents) == 1:
            if len(self.callers) == 0:
                return True
        return False

    def update_parent_to(self, old_address, new_address):
        index = self.parents.index(old_address)
        if new_address in self.parents:
            self.parents.pop(index)  # we already have it so just remove the old
        else:
            self.parents[index] = new_address  # its new so swap it

    def update_caller_to(self, old_address, new_address):
        index = self.callers.index(old_address)
        self.callers[index] = new_address
        temp_callers = []
        for caller in self.callers:
            if caller not in temp_callers:
                temp_callers.append(caller)
        self.callers = temp_callers

    def set_extra_string(self, text):
        if len(text.strip()):
            self.extraString = self.extraString + "\n" + text.strip()

    def get_extra_string(self):
        return self.extraString

    def set_sub_function_type(self, t):
        self.subFunctionType = t

    def get_sub_function_type(self):
        return self.subFunctionType

    def has_no_callers(self):
        if len(self.callers) > 0:
            return False
        return True

    def has_single_or_no_parent(self):
        if len(self.parents) > 1:
            return False
        return True

    def has_single_child(self):
        if len(self.jumps) == 1:
            return True
        return False

    def remove_all_internal_parents(self):
        death_list = []
        for parent in self.parents:
            # if parent > self.start_address and parent < self.end_address:
            if self.start_address < parent < self.end_address:
                death_list.append(parent)
        for death in death_list:
            self.parents.remove(death)

    def is_function_head(self):
        if len(self.parents) == 0 and len(self.callers) != 0:
            return True
        return False
        
    def append_all_children(self, children, tree):
        children.append(self)  # add me
        if len(self.jumps) > 0:  # if I have children
            for c in self.jumps:  # get them
                f = tree.FunctionTable[c]  # get the actual func
                if f not in children:  # have I already visited
                    f.append_all_children(children, tree)  # add its kids
                    if f not in children:
                        children.append(f)  # add it
