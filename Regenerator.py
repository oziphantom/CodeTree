import sys
import re
from collections import namedtuple
from enum import Enum

g_RegeneratorNames = (":CODE START", ":CODE END", ":DATA BYTES", ":WORDS", ":POINTERS",
                      ":HILOLOOKUP", ":LOHILOOKUP", ":DATA TEXT", ":BLANK LINES",
                      ":REMOVED BYTES", ":FULL COMMENTS", ":SIDE COMMENTS", ":USER LABELS",
                      ":DISABLED HILO LABELS", ":USER HILO", ":TAB SIZE", ":LOAD OFFSET",
                      ":SYSTEM" )
                    
RegeneratorDataSet_t = namedtuple("Regenerator", "codeStart,codeEnd,data,words,pointers,hilo,lohi"\
                                ",text,blankLines,removed,fullComments,sideComments,userLabels"\
                                ",userHiLo,tabSize,loadOffset,system")
g_RegeneratorData = []
g_RegeneratorTupple = []

class eRegeneratorDataTypes(Enum):
    CodeStart = 0
    CodeEnd = 1
    Data = 2
    Words = 3
    Pointers = 4
    HiLo = 5
    LoHi = 6
    Text = 7
    BlankLines = 8
    Removed = 9
    FullComments = 10
    SideComments = 11
    UserLabels = 12
    UserHiLo = 13
    TabeSize = 14
    LoadOffset = 15
    System = 16

def getRegenerator():
    global g_RegeneratorTupple
    return g_RegeneratorTupple
    
def Regenerator_ParseFile(file):
    mode = 0
    global g_RegeneratorData
    g_RegeneratorData = [0, 0, [], [], [], [], [], [], [], [], {}, {}, {}, [], [],0 ,0 ,"C64"]
    ptrTable = (Regenerator_OneHex, #Start
                Regenerator_OneHex, #End
                Regenerator_HexRange, #data
                Regenerator_HexRange, #words
                Regenerator_HexRangeOffset, #pointers
                Regenerator_HexRangeOffset, #hilo
                Regenerator_HexRangeOffset, #lohi
                Regenerator_HexRange, #text
                Regenerator_SingleHex, #removed lines
                Regenerator_HexRange, #removed bytes
                Regenerator_HexString, #full comments
                Regenerator_HexString, #side comments
                Regenerator_HexString, #user labels
                Regenerator_SingleHex, #disabled hilo
                Regenerator_UserHiLo, #user hi lo
                Regenerator_OneHex, #tab size
                Regenerator_OneHex, #load offset
                Regenerator_OneString #system
               )

    with open(file) as f:
        lines = f.read().splitlines()
        for l in lines:
            line = l.strip()
            if l.startswith(':'):                
                mode = g_RegeneratorNames.index(line)
            else:
                ptrTable[mode](line, mode)

    global g_RegeneratorTupple
    g_RegeneratorTupple = RegeneratorDataSet_t(g_RegeneratorData[0], g_RegeneratorData[1], g_RegeneratorData[2], 
                                               g_RegeneratorData[3], g_RegeneratorData[4], g_RegeneratorData[5], 
                                               g_RegeneratorData[6], g_RegeneratorData[7], g_RegeneratorData[8], 
                                               g_RegeneratorData[9], g_RegeneratorData[10], g_RegeneratorData[11], 
                                               g_RegeneratorData[12], g_RegeneratorData[13], g_RegeneratorData[14],
                                               g_RegeneratorData[15], g_RegeneratorData[16])

def Regenerator_OneHex(line, mode):
    addr = int(line, 16)
    global g_RegeneratorData
    g_RegeneratorData[mode] = addr

def Regenerator_HexRange(line, mode):  
    parts = line.split("-")
    addr1 = int(parts[0], 16)
    addr2 = int(parts[1], 16)
    global g_RegeneratorData
    g_RegeneratorData[mode].append((addr1, addr2))

def Regenerator_HexRangeOffset(line, mode):
    parts = line.split("-")
    addr1 = int(parts[0], 16)
    addr2 = int(parts[1], 16)
    offset = int(parts[2], 16)
    global g_RegeneratorData
    g_RegeneratorData[mode].append((addr1, addr2, offset))

def Regenerator_SingleHex(line, mode):
    addr = int(line, 16)
    global g_RegeneratorData
    g_RegeneratorData[mode].append(addr)

def Regenerator_HexString(line, mode):
    space = line.index(" ")
    addr = int(line[:space], 16)
    global g_RegeneratorData
    #g_RegeneratorData[mode].append((addr, line[space+1:]))
    g_RegeneratorData[mode][addr]=line[space+1:]

def Regenerator_UserHiLo(line, mode):
    parts = line.split("-")
    addr1 = int(parts[0], 16)
    addr2 = int(parts[1], 16)
    addr3 = int(parts[2], 16)
    hiLo = int(parts[3], 16)
    global g_RegeneratorData
    g_RegeneratorData[mode].append((addr1, addr2, addr3, hiLo))

def Regenerator_OneString(line, mode):
    global g_RegeneratorData
    g_RegeneratorData[mode] = line

def Regenerator_getLabelForAddr(addr):
    if len(g_RegeneratorTupple) > 0:
        if addr in g_RegeneratorTupple.userLabels:
            return g_RegeneratorTupple.userLabels[addr]
    return "{:4X}".format(addr)