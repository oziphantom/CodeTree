from enum import Enum
class eSubFunctionType(Enum):
    Unknown = "Unknown"
    Run = "Run"
    IfBlock = "If"
    IfElseBlock = "IfElse"
    Loop = "Loop"
    FuncGroup = "FuncGroup"

