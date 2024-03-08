from enum import Enum

class Pipeline(Enum):
    b = 1
    i0 = 2
    i1 = 3
    m = 4
    l = 5
    s = 6
    f0 = 7
    f1 = 8
    i0or1 = 9


class Instruction:
    def __init__(self, name, latency, throughput, pipeline0, pipeline1=None):
        self.name = name
        self.latency = latency
        self.throughput = throughput
        self.pipeline0 = pipeline0
        self.pipeline1 = pipeline1


EOR = Instruction("eor", 1, 2, Pipeline.i0or1)
EOR_ROR = Instruction("eor_ror", 2, 1, Pipeline.m)
ROR = Instruction("ror", 1, 2, Pipeline.m)
BIC= Instruction("bic", 1, 2, Pipeline.i0, Pipeline.i0or1)

class Dependency:
    def __init__(self, depends_on = None, instruction = None, dependent_on_by = None):
        self.instruction = instruction
        self.depends_on = []
        self.dependent_on_by = []
        if depends_on is not None:
            self.depends_on.append(depends_on)
        if dependent_on_by is not None:
            self.dependent_on_by.append(dependent_on_by)
    
    def add_dependency(self, depends_on):
        self.depends_on.append(depends_on)
    
    def add_dependent_on_by(self, dependent_on_by):
        self.dependent_on_by.append(dependent_on_by)


# Registers
X0 = Dependency()
X1 = Dependency()
X2 = Dependency()
X3 = Dependency()
X4 = Dependency()
X5 = Dependency()
X6 = Dependency()
X7 = Dependency()
X8 = Dependency()
X9 = Dependency()
X10 = Dependency()
X11 = Dependency()
X12 = Dependency()
X13 = Dependency()
X14 = Dependency()
X15 = Dependency()
X16 = Dependency()
X17 = Dependency()
X18 = Dependency()
X19 = Dependency()
X20 = Dependency()
X21 = Dependency()
X22 = Dependency()
X23 = Dependency()
X24 = Dependency()
X25 = Dependency()
X26 = Dependency()
X27 = Dependency()
X28 = Dependency()
X29 = Dependency()
X30 = Dependency()
X31 = Dependency()



# Load the data lanes into registers
# Lane[x,y] => reg[5y+x]
L00_LD = Dependency(X0)
L01_LD = Dependency(X5)
L02_LD = Dependency(X10)
L03_LD = Dependency(X15)
L04_LD = Dependency(X20)
L10_LD = Dependency(X1)
L11_LD = Dependency(X6)
L12_LD = Dependency(X11)
L13_LD = Dependency(X16)
L14_LD = Dependency(X21)
L20_LD = Dependency(X2)
L21_LD = Dependency(X7)
L22_LD = Dependency(X12)
L23_LD = Dependency(X17)
L24_LD = Dependency(X22)
L30_LD = Dependency(X3)
L31_LD = Dependency(X8)
L32_LD = Dependency(X13)
L33_LD = Dependency(X18)
L34_LD = Dependency(X23)
L40_LD = Dependency(X4)
L41_LD = Dependency(X9)
L42_LD = Dependency(X14)
L43_LD = Dependency(X19)
L44_LD = Dependency(X24)


# calculate C
C0_0 = Dependency([X25, L00_LD, L01_LD], EOR)
C0_1 = Dependency([C0_0, L02_LD], EOR)
C0_2 = Dependency([C0_0, L03_LD], EOR)
C0_3 = Dependency([C0_0, L04_LD], EOR)
C0 = Dependency(C0_3)

C1_0 = Dependency([X26, L10_LD, L11_LD], EOR)
C1_1 = Dependency([C1_0, L12_LD], EOR)
C1_2 = Dependency([C1_0, L13_LD], EOR)
C1_3 = Dependency([C1_0, L14_LD], EOR)
C1 = Dependency(C1_3)

C2_0 = Dependency([X27, L20_LD, L21_LD], EOR)
C2_1 = Dependency([C2_0, L22_LD], EOR)
C2_2 = Dependency([C2_0, L23_LD], EOR)
C2_3 = Dependency([C2_0, L24_LD], EOR)
C2 = Dependency(C2_3)

C3_0 = Dependency([X28, L30_LD, L31_LD], EOR)
C3_1 = Dependency([C3_0, L32_LD], EOR)
C3_2 = Dependency([C3_0, L33_LD], EOR)
C3_3 = Dependency([C3_0, L34_LD], EOR)
C3 = Dependency(C3_3)

C4_0 = Dependency([X29, L40_LD, L41_LD], EOR)
C4_1 = Dependency([C4_0, L42_LD], EOR)
C4_2 = Dependency([C4_0, L43_LD], EOR)
C4_3 = Dependency([C4_0, L44_LD], EOR)
C4 = Dependency(C4_3)


# calculate D
'''
    EOR D_X0, C_X4, ROR C_X1, #1        ; C_X1: 1, C_X4: 1
    EOR D_X2, C_X1, ROR C_X3, #1        ; C_X1: *, C_X3: 1, C_X4: 1
    EOR D_X4, C_X3, ROR C_X0, #1        ; C_X0: 1, C_X3: *, C_X4: 1
    EOR D_X1, C_X0, ROR C_X2, #1        ; C_X0: *, C_X2: 1, C_X4: 1
    EOR D_X3, C_X2, ROR C_X4, #1        ; C_X2: *, C_X4: *
'''

D0 = Dependency([X30, C1, C4], EOR_ROR)
D2 = Dependency([X26, C1, C3, ], EOR_ROR)
D4 = Dependency([X28, C3, C0], EOR_ROR)
D1 = Dependency([X26, C0, C2], EOR_ROR)
D3 = Dependency([X27, C2, C4], EOR_ROR)





