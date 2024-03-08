.global keccak
.type keccak, %function

/* Lane to register mapping: Lane[x,y] => reg[5y+x] */
L_X0Y0 .req X0
L_X0Y1 .req X5
L_X0Y2 .req X10
L_X0Y3 .req X15
L_X0Y4 .req X20

L_X1Y0 .req X1
L_X1Y1 .req X6
L_X1Y2 .req X11
L_X1Y3 .req X16
L_X1Y4 .req X21

L_X2Y0 .req X2
L_X2Y1 .req X7
L_X2Y2 .req X12
L_X2Y3 .req X17
L_X2Y4 .req X22

L_X3Y0 .req X3
L_X3Y1 .req X8
L_X3Y2 .req X13
L_X3Y3 .req X18
L_X3Y4 .req X23

L_X4Y0 .req X4
L_X4Y1 .req X9
L_X4Y2 .req X14
L_X4Y3 .req X19
L_X4Y4 .req X24


; X0: address of input message
; X1: address of output hash
keccak:
    /* Procedure call standard */
    ; TODO

    /* Move the address to X30*/
    MOV X30, X0 

    /* Load the string into state array i.e. X0 to X24 */
    LDP X0, X1, [X30, #0]
    LDP X2, X3, [X30, #16]
    LDP X4, X5, [X30, #32]
    LDP X6, X7, [X30, #48]
    LDP X8, X9, [X30, #64]
    LDP X10, X11, [X30, #80]
    LDP X12, X13, [X30, #96]
    LDP X14, X15, [X30, #112]
    LDP X16, X17, [X30, #128]
    LDP X18, X19, [X30, #144]
    LDP X20, X21, [X30, #160]
    LDP X22, X23, [X30, #176]
    LDR X24, [X30, #192]

    /* Go to theta */
    B theta


/* X to C mapping used in theta */
C_X0 .req X25
C_X1 .req X26
C_X2 .req X27
C_X3 .req X28
C_X4 .req X29


/* X to D mapping used in theta */
D_X0 .req X30
D_X1 .req C_X0
D_X2 .req C_X1
D_X3 .req C_X2
D_X4 .req C_X3


/*
theta

D[X] = C[(X - 1) % 5] XOR RROT(C[(X + 1) % 5], 1)

D[x] = C[X-1] XOR RROT(C[X+1], 1)

D[0] = C[4] ^ C[1] >> 1
D[1] = C[0] ^ C[2] >> 1
D[2] = C[1] ^ C[3] >> 1
D[3] = C[2] ^ C[4] >> 1
D[4] = C[3] ^ C[0] >> 1

D_X0 = X30
D_X2 = C_X1
D_X4 = C_X3

x = 0, (x - 1) % 5 = 4
x = 1, (x - 1) % 5 = 0
x = 2, (x - 1) % 5 = 1
x = 3, (x - 1) % 5 = 2
x = 4, (x - 1) % 5 = 3

x = 0, (x + 1) % 5 = 1
x = 1, (x + 1) % 5 = 2
x = 2, (x + 1) % 5 = 3
x = 3, (x + 1) % 5 = 4
x = 4, (x + 1) % 5 = 0

z = 0, (z - 1) % 64 = 63
z = 1, (z - 1) % 64 = 0
z = 2, (z - 1) % 64 = 1
z = 3, (z - 1) % 64 = 2
...
z = 63, (z - 1) % 64 = 62



/*
            Table of rho offsets:
        x=3     x=4     x=0     x=1     x=2
y=2     153     231     3       10      171
y=1     55      276     36      300     6
y=0     28      91      0       1       190
y=4     120     78      210     66      253
y=3     21      136     105     45      15

            Table of rho offsets mod 64:
        x=3     x=4     x=0     x=1     x=2
y=2     25      39      3       10      43
y=1     55      20      36      44      6
y=0     28      27      0       1       62
y=4     56      14      18      2       61
y=3     21      8       41      45      15
*/
/* Rho offsets */
L_X0Y0_ROR_OFFSET .equ 0
L_X0Y1_ROR_OFFSET .equ 36
L_X0Y2_ROR_OFFSET .equ 3
L_X0Y3_ROR_OFFSET .equ 41
L_X0Y4_ROR_OFFSET .equ 18

L_X1Y0_ROR_OFFSET .equ 1
L_X1Y1_ROR_OFFSET .equ 44
L_X1Y2_ROR_OFFSET .equ 10
L_X1Y3_ROR_OFFSET .equ 45
L_X1Y4_ROR_OFFSET .equ 2

L_X2Y0_ROR_OFFSET .equ 62
L_X2Y1_ROR_OFFSET .equ 6
L_X2Y2_ROR_OFFSET .equ 43
L_X2Y3_ROR_OFFSET .equ 15
L_X2Y4_ROR_OFFSET .equ 61

L_X3Y0_ROR_OFFSET .equ 28
L_X3Y1_ROR_OFFSET .equ 55
L_X3Y2_ROR_OFFSET .equ 25
L_X3Y3_ROR_OFFSET .equ 21
L_X3Y4_ROR_OFFSET .equ 56

L_X4Y0_ROR_OFFSET .equ 27
L_X4Y1_ROR_OFFSET .equ 20
L_X4Y2_ROR_OFFSET .equ 39
L_X4Y3_ROR_OFFSET .equ 8
L_X4Y4_ROR_OFFSET .equ 14



/* Rho */
rho:
    
    B chi



/* pi 

pi does not deserve a separate function as it is just a permutation of lanes.
We just precompute the new indices and use aliases with underscores at the end
to denote the new locations.

A′[x, y]=A[(x + 3y) mod 5, x].

A'[0, 0] = A[0, 0]
A'[0, 1] = A[3, 0]
A'[0, 2] = A[1, 0]
A'[0, 3] = A[4, 0]
A'[0, 4] = A[2, 0]

A'[1, 0] = A[1, 1]
A'[1, 1] = A[4, 1]
A'[1, 2] = A[2, 1]
A'[1, 3] = A[0, 1]
A'[1, 4] = A[3, 1]

A'[2, 0] = A[2, 2]
A'[2, 1] = A[0, 2]
A'[2, 2] = A[3, 2]
A'[2, 3] = A[1, 2]
A'[2, 4] = A[4, 2]

A'[3, 0] = A[3, 3]
A'[3, 1] = A[1, 3]
A'[3, 2] = A[4, 3]
A'[3, 3] = A[2, 3]
A'[3, 4] = A[0, 3]

A'[4, 0] = A[4, 4]
A'[4, 1] = A[2, 4]
A'[4, 2] = A[0, 4]
A'[4, 3] = A[3, 4]

*/

L_X0Y0_ .req L_X0Y0
L_X0Y1_ .req L_X3Y0
L_X0Y2_ .req L_X1Y0
L_X0Y3_ .req L_X4Y0
L_X0Y4_ .req L_X2Y0

L_X1Y0_ .req L_X1Y1
L_X1Y1_ .req L_X4Y1
L_X1Y2_ .req L_X2Y1
L_X1Y3_ .req L_X0Y1
L_X1Y4_ .req L_X3Y1

L_X2Y0_ .req L_X2Y2
L_X2Y1_ .req L_X0Y2
L_X2Y2_ .req L_X3Y2
L_X2Y3_ .req L_X1Y2
L_X2Y4_ .req L_X4Y2

L_X3Y0_ .req L_X3Y3
L_X3Y1_ .req L_X1Y3
L_X3Y2_ .req L_X4Y3
L_X3Y3_ .req L_X2Y3
L_X3Y4_ .req L_X0Y3

L_X4Y0_ .req L_X4Y4
L_X4Y1_ .req L_X2Y4
L_X4Y2_ .req L_X0Y4
L_X4Y3_ .req L_X3Y4



/*
chi
        
Since we can't work on live data here, we need to change the mapping of lanes
to registers such that the output lane is not the same as the input lane or any
other lane that must not be modified yet. 
*/

L_X0Y0_CHI_OUT .req X26
L_X0Y1_CHI_OUT .req X27
L_X0Y2_CHI_OUT .req X28
L_X0Y3_CHI_OUT .req X29
L_X0Y4_CHI_OUT .req X30

L_X1Y0_CHI_OUT .req X0
L_X1Y1_CHI_OUT .req X1
L_X1Y2_CHI_OUT .req X2
L_X1Y3_CHI_OUT .req X3
L_X1Y4_CHI_OUT .req X4

L_X2Y0_CHI_OUT .req X5
L_X2Y1_CHI_OUT .req X6
L_X2Y2_CHI_OUT .req X7
L_X2Y3_CHI_OUT .req X8
L_X2Y4_CHI_OUT .req X9

L_X3Y0_CHI_OUT .req X10
L_X3Y1_CHI_OUT .req X11
L_X3Y2_CHI_OUT .req X12
L_X3Y3_CHI_OUT .req X13
L_X3Y4_CHI_OUT .req X14

L_X4Y0_CHI_OUT .req X15
L_X4Y1_CHI_OUT .req X16
L_X4Y2_CHI_OUT .req X17
L_X4Y3_CHI_OUT .req X18
L_X4Y4_CHI_OUT .req X19

/*
L[x,y]  = L[x,y] ^ ((L[x + 1, y] ^ ~(uint64)0 ) & L[x + 2, y])
        = L[x,y] ^ (~L[x + 1, y]) & L[x + 2, y])
        = (~L[x + 1, y]) & L[x + 2, y]) ^ L[x,y]
        = (L[x + 2, y] & ~L[x + 1, y]) ^ L[x,y]
*/

/* chi */
chi:
    


    /* Go to iota */
    B iota


/* Iota */


; KECCAK round
.macro rnd
    ; Theta --------------------------------------------------------------------
    /* Calculate 'C' and store it in X25-x29 */
    /* Sheet 0 */
    EOR C_X0, L_X0Y0, L_X0Y1
    EOR C_X0, C_X0, L_X0Y2
    EOR C_X0, C_X0, L_X0Y3
    EOR C_X0, C_X0, L_X0Y4

    /* Sheet 1 */
    EOR C_X1, L_X1Y0, L_X1Y1
    EOR C_X1, C_X1, L_X1Y2
    EOR C_X1, C_X1, L_X1Y3
    EOR C_X1, C_X1, L_X1Y4

    /* Sheet 2 */
    EOR C_X2, L_X2Y0, L_X2Y1
    EOR C_X2, C_X2, L_X2Y2
    EOR C_X2, C_X2, L_X2Y3
    EOR C_X2, C_X2, L_X2Y4

    /* Sheet 3 */
    EOR C_X3, L_X3Y0, L_X3Y1
    EOR C_X3, C_X3, L_X3Y2
    EOR C_X3, C_X3, L_X3Y3
    EOR C_X3, C_X3, L_X3Y4

    /* Sheet 4 */
    EOR C_X4, L_X4Y0, L_X4Y1
    EOR C_X4, C_X4, L_X4Y2
    EOR C_X4, C_X4, L_X4Y3
    EOR C_X4, C_X4, L_X4Y4


    /* Calculate 'D' and store it in X25-x28 and X30 */
    EOR D_X0, C_X4, ROR C_X1, #1        ; C_X1: 1, C_X4: 1
    EOR D_X2, C_X1, ROR C_X3, #1        ; C_X1: *, C_X3: 1, C_X4: 1
    EOR D_X4, C_X3, ROR C_X0, #1        ; C_X0: 1, C_X3: *, C_X4: 1
    EOR D_X1, C_X0, ROR C_X2, #1        ; C_X0: *, C_X2: 1, C_X4: 1
    EOR D_X3, C_X2, ROR C_X4, #1        ; C_X2: *, C_X4: *


    /* XOR all lanes with respective 'D' */
    /* Sheet 1 */
    EOR L_X0Y0, L_X0Y0, D_X0
    EOR L_X0Y1, L_X0Y1, D_X0
    EOR L_X0Y2, L_X0Y2, D_X0
    EOR L_X0Y3, L_X0Y3, D_X0
    EOR L_X0Y4, L_X0Y4, D_X0

    /* Sheet 2 */
    EOR L_X1Y0, L_X1Y0, D_X1
    EOR L_X1Y1, L_X1Y1, D_X1
    EOR L_X1Y2, L_X1Y2, D_X1
    EOR L_X1Y3, L_X1Y3, D_X1
    EOR L_X1Y4, L_X1Y4, D_X1

    /* Sheet 3 */
    EOR L_X2Y0, L_X2Y0, D_X2
    EOR L_X2Y1, L_X2Y1, D_X2
    EOR L_X2Y2, L_X2Y2, D_X2
    EOR L_X2Y3, L_X2Y3, D_X2
    EOR L_X2Y4, L_X2Y4, D_X2

    /* Sheet 4 */
    EOR L_X3Y0, L_X3Y0, D_X3
    EOR L_X3Y1, L_X3Y1, D_X3
    EOR L_X3Y2, L_X3Y2, D_X3
    EOR L_X3Y3, L_X3Y3, D_X3
    EOR L_X3Y4, L_X3Y4, D_X3

    /* Sheet 5 */
    EOR L_X4Y0, L_X4Y0, D_X4
    EOR L_X4Y1, L_X4Y1, D_X4
    EOR L_X4Y2, L_X4Y2, D_X4
    EOR L_X4Y3, L_X4Y3, D_X4
    EOR L_X4Y4, L_X4Y4, D_X4



    ; Rho ----------------------------------------------------------------------
    /* rotate all the lanes with respective offsets */
    ROR L_X0Y0, L_X0Y0, L_X0Y0_ROR_OFFSET
    ROR L_X0Y1, L_X0Y1, L_X0Y1_ROR_OFFSET
    ROR L_X0Y2, L_X0Y2, L_X0Y2_ROR_OFFSET
    ROR L_X0Y3, L_X0Y3, L_X0Y3_ROR_OFFSET
    ROR L_X0Y4, L_X0Y4, L_X0Y4_ROR_OFFSET

    ROR L_X1Y0, L_X1Y0, L_X1Y0_ROR_OFFSET
    ROR L_X1Y1, L_X1Y1, L_X1Y1_ROR_OFFSET
    ROR L_X1Y2, L_X1Y2, L_X1Y2_ROR_OFFSET
    ROR L_X1Y3, L_X1Y3, L_X1Y3_ROR_OFFSET
    ROR L_X1Y4, L_X1Y4, L_X1Y4_ROR_OFFSET

    ROR L_X2Y0, L_X2Y0, L_X2Y0_ROR_OFFSET
    ROR L_X2Y1, L_X2Y1, L_X2Y1_ROR_OFFSET
    ROR L_X2Y2, L_X2Y2, L_X2Y2_ROR_OFFSET
    ROR L_X2Y3, L_X2Y3, L_X2Y3_ROR_OFFSET
    ROR L_X2Y4, L_X2Y4, L_X2Y4_ROR_OFFSET

    ROR L_X3Y0, L_X3Y0, L_X3Y0_ROR_OFFSET
    ROR L_X3Y1, L_X3Y1, L_X3Y1_ROR_OFFSET
    ROR L_X3Y2, L_X3Y2, L_X3Y2_ROR_OFFSET
    ROR L_X3Y3, L_X3Y3, L_X3Y3_ROR_OFFSET
    ROR L_X3Y4, L_X3Y4, L_X3Y4_ROR_OFFSET

    ROR L_X4Y0, L_X4Y0, L_X4Y0_ROR_OFFSET
    ROR L_X4Y1, L_X4Y1, L_X4Y1_ROR_OFFSET
    ROR L_X4Y2, L_X4Y2, L_X4Y2_ROR_OFFSET
    ROR L_X4Y3, L_X4Y3, L_X4Y3_ROR_OFFSET
    ROR L_X4Y4, L_X4Y4, L_X4Y4_ROR_OFFSET


    ; Pi -----------------------------------------------------------------------
    /* pi is not a separate function so just go straight to chi */


    ; Chi ----------------------------------------------------------------------
    /* x0y0 */
    BIC X25, L_X2Y0_, L_X1Y0_
    EOR L_X0Y0_, X25, L_X0Y0_CHI_OUT

    /* x0y1 */
    BIC X25, L_X2Y1_, L_X1Y1_
    EOR L_X0Y1_, X25, L_X0Y1_CHI_OUT

    /* x0y2 */
    BIC X25, L_X2Y2_, L_X1Y2_
    EOR L_X0Y2_, X25, L_X0Y2_CHI_OUT

    /* x0y3 */
    BIC X25, L_X2Y3_, L_X1Y3_
    EOR L_X0Y3_, X25, L_X0Y3_CHI_OUT

    /* x0y4 */
    BIC X25, L_X2Y4_, L_X1Y4_
    EOR L_X0Y4_, X25, L_X0Y4_CHI_OUT

    /* x1y0 */
    BIC X25, L_X3Y0_, L_X2Y0_
    EOR L_X1Y0_, X25, L_X1Y0_CHI_OUT

    /* x1y1 */
    BIC X25, L_X3Y1_, L_X2Y1_
    EOR L_X1Y1_, X25, L_X1Y1_CHI_OUT

    /* x1y2 */
    BIC X25, L_X3Y2_, L_X2Y2_
    EOR L_X1Y2_, X25, L_X1Y2_CHI_OUT

    /* x1y3 */
    BIC X25, L_X3Y3_, L_X2Y3_
    EOR L_X1Y3_, X25, L_X1Y3_CHI_OUT

    /* x1y4 */
    BIC X25, L_X3Y4_, L_X2Y4_
    EOR L_X1Y4_, X25, L_X1Y4_CHI_OUT

    /* x2y0 */
    BIC X25, L_X4Y0_, L_X3Y0_
    EOR L_X2Y0_, X25, L_X2Y0_CHI_OUT

    /* x2y1 */
    BIC X25, L_X4Y1_, L_X3Y1_
    EOR L_X2Y1_, X25, L_X2Y1_CHI_OUT

    /* x2y2 */
    BIC X25, L_X4Y2_, L_X3Y2_
    EOR L_X2Y2_, X25, L_X2Y2_CHI_OUT

    /* x2y3 */
    BIC X25, L_X4Y3_, L_X3Y3_
    EOR L_X2Y3_, X25, L_X2Y3_CHI_OUT

    /* x2y4 */
    BIC X25, L_X4Y4_, L_X3Y4_
    EOR L_X2Y4_, X25, L_X2Y4_CHI_OUT

    /* x3y0 */
    BIC X25, L_X0Y0_, L_X4Y0_
    EOR L_X3Y0_, X25, L_X3Y0_CHI_OUT

    /* x3y1 */
    BIC X25, L_X0Y1_, L_X4Y1_
    EOR L_X3Y1_, X25, L_X3Y1_CHI_OUT

    /* x3y2 */
    BIC X25, L_X0Y2_, L_X4Y2_
    EOR L_X3Y2_, X25, L_X3Y2_CHI_OUT

    /* x3y3 */
    BIC X25, L_X0Y3_, L_X4Y3_
    EOR L_X3Y3_, X25, L_X3Y3_CHI_OUT

    /* x3y4 */
    BIC X25, L_X0Y4_, L_X4Y4_
    EOR L_X3Y4_, X25, L_X3Y4_CHI_OUT

    /* x4y0 */
    BIC X25, L_X1Y0_, L_X0Y0_
    EOR L_X4Y0_, X25, L_X4Y0_CHI_OUT

    /* x4y1 */
    BIC X25, L_X1Y1_, L_X0Y1_
    EOR L_X4Y1_, X25, L_X4Y1_CHI_OUT

    /* x4y2 */
    BIC X25, L_X1Y2_, L_X0Y2_
    EOR L_X4Y2_, X25, L_X4Y2_CHI_OUT

    /* x4y3 */
    BIC X25, L_X1Y3_, L_X0Y3_
    EOR L_X4Y3_, X25, L_X4Y3_CHI_OUT

    /* x4y4 */
    BIC X25, L_X1Y4_, L_X0Y4_
    EOR L_X4Y4_, X25, L_X4Y4_CHI_OUT


    ; Iota ---------------------------------------------------------------------
    