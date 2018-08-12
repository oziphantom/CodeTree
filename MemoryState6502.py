class MemoryState6502(object):
    def __init__(self):
        self.R = False
        self.W = False
        self.Vector = False
        self.VectorPair = 0
        self.VectorHi = False
        self.Address = 0
        self.Execute = False
        self.Unknown = True

    def set_address(self, addr):
        self.Address = addr

    def set_r(self):
        self.R = True
        self.Unknown = False

    def set_w(self):
        self.W = True
        self.Unknown = False

    def set_vector(self, pair, vector_is_hi):
        self.Vector = True
        self.Unknown = False
        self.VectorPair = pair
        self.VectorHi = vector_is_hi

    def set_execute(self):
        self.Execute = True
        self.Unknown = False

    def does_r(self):
        return self.R

    def does_w(self):
        return self.W

    def does_exectue(self):
        return self.Execute

    def is_vector(self):
        return self.Vector

    def is_unknown(self):
        return self.Unknown

    def get_description(self):
        out = "Addr {:4X} is ".format(self.Address)
        if self.R:
            out += "R"
        if self.W:
            out += "W"
        out += " "
        if self.Vector:
            out += "VECTOR "
            if self.VectorHi:
                out += "HI off {:4X}".format(self.VectorPair)
            else:
                out += "LO, Paired with {:4X}".format(self.VectorPair)
