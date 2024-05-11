

// Lane to register mapping: Lane[x,y] => reg[5y+x]
L_X0Y0 .req x0
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



/* X to C mappings */
C_X0 .req X25
C_X1 .req X26
C_X2 .req X27
C_X3 .req X28
C_X4 .req X29



/* X to D mapping used in theta */
D_X0 .req X30
D_X1 .req x25
D_X2 .req x26
D_X3 .req x27
D_X4 .req x28



/* Theta
    # instructions: 50
    # avg throughput: 2
    # estimated expected cycles: 25
    # estimated time @ 1.8ghz: 25*0.556 = 13.9ns
    # estimated total time: 13.9ns * 24 = 333.6ns
*/
.macro theta

    STP X29, X30, [SP, #-16]!

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
    EOR D_X0, C_X4, C_X1, ROR #63        // C_X1: 1, C_X4: 1
    EOR D_X2, C_X1, C_X3, ROR #63        // C_X1: *, C_X3: 1, C_X4: 1
    EOR D_X4, C_X3, C_X0, ROR #63        // C_X0: 1, C_X3: *, C_X4: 1
    EOR D_X1, C_X0, C_X2, ROR #63        // C_X0: *, C_X2: 1, C_X4: 1
    EOR D_X3, C_X2, C_X4, ROR #63        // C_X2: *, C_X4: *



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

    LDP X29, X30, [SP], #16

.endm







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

            Table of rho offsets mod 64 for ROR (64-a)%64:
        x=3     x=4     x=0     x=1     x=2
y=2     39      25      61      54      21
y=1     9       44      28      20      58
y=0     36      37      0       63      2
y=4     8       50      46      62      3
y=3     43      56      23      19      49


*/
/* Rho offsets */

.equ L_X0Y0_ROR_OFFSET, 0
.equ L_X0Y1_ROR_OFFSET, 28
.equ L_X0Y2_ROR_OFFSET, 61
.equ L_X0Y3_ROR_OFFSET, 23
.equ L_X0Y4_ROR_OFFSET, 46

.equ L_X1Y0_ROR_OFFSET, 63
.equ L_X1Y1_ROR_OFFSET, 20
.equ L_X1Y2_ROR_OFFSET, 54
.equ L_X1Y3_ROR_OFFSET, 19
.equ L_X1Y4_ROR_OFFSET, 62

.equ L_X2Y0_ROR_OFFSET, 2
.equ L_X2Y1_ROR_OFFSET, 58
.equ L_X2Y2_ROR_OFFSET, 21
.equ L_X2Y3_ROR_OFFSET, 49
.equ L_X2Y4_ROR_OFFSET, 3

.equ L_X3Y0_ROR_OFFSET, 36
.equ L_X3Y1_ROR_OFFSET, 9
.equ L_X3Y2_ROR_OFFSET, 39
.equ L_X3Y3_ROR_OFFSET, 43
.equ L_X3Y4_ROR_OFFSET, 8

.equ L_X4Y0_ROR_OFFSET, 37
.equ L_X4Y1_ROR_OFFSET, 44
.equ L_X4Y2_ROR_OFFSET, 25
.equ L_X4Y3_ROR_OFFSET, 56
.equ L_X4Y4_ROR_OFFSET, 50



/* pi 

pi does not deserve a separate function as it is just a permutation of lanes.
We just precompute the new indices and use aliases with underscores at the end
to denote the new locations.

A′[x, y]=A[(x + 3y) mod 5, x].

A[0, 0] -> A'[0, 0]
A[0, 1] -> A'[1, 3]
A[0, 2] -> A'[2, 1]
A[0, 3] -> A'[3, 4]
A[0, 4] -> A'[4, 2]

A[1, 0] -> A'[0, 2]
A[1, 1] -> A'[1, 0]
A[1, 2] -> A'[2, 3]
A[1, 3] -> A'[3, 1]
A[1, 4] -> A'[4, 4]

A[2, 0] -> A'[0, 4]
A[2, 1] -> A'[1, 2]
A[2, 2] -> A'[2, 0]
A[2, 3] -> A'[3, 3]
A[2, 4] -> A'[4, 1]

A[3, 0] -> A'[0, 1]
A[3, 1] -> A'[1, 4]
A[3, 2] -> A'[2, 2]
A[3, 3] -> A'[3, 0]
A[3, 4] -> A'[4, 3]

A[4, 0] -> A'[0, 3]
A[4, 1] -> A'[1, 1]
A[4, 2] -> A'[2, 4]
A[4, 3] -> A'[3, 2]
A[4, 4] -> A'[4, 0]

*/
/* Rho_pi
    # instructions: 26
    # estimated avg throughput: 2
    # expected cycles: 13
    # estimated time @ 1.8ghz: 13*0.556 = 7.3ns
    # estimated total time: 7.3ns * 24 = 175.2ns


*/
.macro rho_pi
    /* rotate all the lanes with respective offsets,
        and place new values in the locations of the
        PI step*/
    ROR L_X0Y0, L_X0Y0, #L_X0Y0_ROR_OFFSET

    ROR x25, L_X1Y0, #L_X1Y0_ROR_OFFSET

    ROR L_X1Y0, L_X1Y1, #L_X1Y1_ROR_OFFSET
    ROR L_X1Y1, L_X4Y1, #L_X4Y1_ROR_OFFSET
    ROR L_X4Y1, L_X2Y4, #L_X2Y4_ROR_OFFSET
    ROR L_X2Y4, L_X4Y2, #L_X4Y2_ROR_OFFSET
    ROR L_X4Y2, L_X0Y4, #L_X0Y4_ROR_OFFSET
    ROR L_X0Y4, L_X2Y0, #L_X2Y0_ROR_OFFSET
    ROR L_X2Y0, L_X2Y2, #L_X2Y2_ROR_OFFSET
    ROR L_X2Y2, L_X3Y2, #L_X3Y2_ROR_OFFSET
    ROR L_X3Y2, L_X4Y3, #L_X4Y3_ROR_OFFSET
    ROR L_X4Y3, L_X3Y4, #L_X3Y4_ROR_OFFSET
    ROR L_X3Y4, L_X0Y3, #L_X0Y3_ROR_OFFSET
    ROR L_X0Y3, L_X4Y0, #L_X4Y0_ROR_OFFSET
    ROR L_X4Y0, L_X4Y4, #L_X4Y4_ROR_OFFSET
    ROR L_X4Y4, L_X1Y4, #L_X1Y4_ROR_OFFSET
    ROR L_X1Y4, L_X3Y1, #L_X3Y1_ROR_OFFSET
    ROR L_X3Y1, L_X1Y3, #L_X1Y3_ROR_OFFSET
    ROR L_X1Y3, L_X0Y1, #L_X0Y1_ROR_OFFSET
    ROR L_X0Y1, L_X3Y0, #L_X3Y0_ROR_OFFSET
    ROR L_X3Y0, L_X3Y3, #L_X3Y3_ROR_OFFSET
    ROR L_X3Y3, L_X2Y3, #L_X2Y3_ROR_OFFSET
    ROR L_X2Y3, L_X1Y2, #L_X1Y2_ROR_OFFSET
    ROR L_X1Y2, L_X2Y1, #L_X2Y1_ROR_OFFSET
    ROR L_X2Y1, L_X0Y2, #L_X0Y2_ROR_OFFSET

    MOV L_X0Y2, x25
.endm



/* chi
    # instructions: 50
    # avg throughput: 2
    # estimated expected cycles: 25
    # estimated time @ 1.8ghz: 25*0.556 = 13.9ns
    # estimated total time: 13.9ns * 24 = 333.6ns
*/
.macro chi

    // Plane 0 -------------
    // X0Y0
    BIC X25, L_X2Y0, L_X1Y0
    BIC X26, L_X0Y0, L_X4Y0
    BIC X27, L_X1Y0, L_X0Y0
    EOR L_X0Y0, L_X0Y0, X25

    // X1Y0
    BIC X25, L_X3Y0, L_X2Y0
    EOR L_X1Y0, L_X1Y0, X25

    // X2Y0
    BIC X25, L_X4Y0, L_X3Y0
    EOR L_X2Y0, L_X2Y0, X25

    // X3Y0
    EOR L_X3Y0, L_X3Y0, X26

    // X4Y0
    EOR L_X4Y0, L_X4Y0, X27


    // Plane 1 -------------
    // X0Y1
    BIC X25, L_X2Y1, L_X1Y1
    BIC X26, L_X0Y1, L_X4Y1
    BIC X27, L_X1Y1, L_X0Y1
    EOR L_X0Y1, L_X0Y1, X25

    // X1Y1
    BIC X25, L_X3Y1, L_X2Y1
    EOR L_X1Y1, L_X1Y1, X25

    // X2Y1
    BIC X25, L_X4Y1, L_X3Y1
    EOR L_X2Y1, L_X2Y1, X25

    // X3Y1
    EOR L_X3Y1, L_X3Y1, X26

    // X4Y1
    EOR L_X4Y1, L_X4Y1, X27


    // Plane 2 -------------
    // X0Y2
    BIC X25, L_X2Y2, L_X1Y2
    BIC X26, L_X0Y2, L_X4Y2
    BIC X27, L_X1Y2, L_X0Y2
    EOR L_X0Y2, L_X0Y2, X25

    // X1Y2
    BIC X25, L_X3Y2, L_X2Y2
    EOR L_X1Y2, L_X1Y2, X25

    // X2Y2
    BIC X25, L_X4Y2, L_X3Y2
    EOR L_X2Y2, L_X2Y2, X25

    // X3Y2
    EOR L_X3Y2, L_X3Y2, X26

    // X4Y2
    EOR L_X4Y2, L_X4Y2, X27


    // Plane 3 -------------
    // X0Y3
    BIC X25, L_X2Y3, L_X1Y3
    BIC X26, L_X0Y3, L_X4Y3
    BIC X27, L_X1Y3, L_X0Y3
    EOR L_X0Y3, L_X0Y3, X25

    // X1Y3
    BIC X25, L_X3Y3, L_X2Y3
    EOR L_X1Y3, L_X1Y3, X25

    // X2Y3
    BIC X25, L_X4Y3, L_X3Y3
    EOR L_X2Y3, L_X2Y3, X25

    // X3Y3
    EOR L_X3Y3, L_X3Y3, X26

    // X4Y3
    EOR L_X4Y3, L_X4Y3, X27


    // Plane 4 -------------
    // X0Y4
    BIC X25, L_X2Y4, L_X1Y4
    BIC X26, L_X0Y4, L_X4Y4
    BIC X27, L_X1Y4, L_X0Y4
    EOR L_X0Y4, L_X0Y4, X25

    // X1Y4
    BIC X25, L_X3Y4, L_X2Y4
    EOR L_X1Y4, L_X1Y4, X25

    // X2Y4
    BIC X25, L_X4Y4, L_X3Y4
    EOR L_X2Y4, L_X2Y4, X25

    // X3Y4
    EOR L_X3Y4, L_X3Y4, X26

    // X4Y4
    EOR L_X4Y4, L_X4Y4, X27


.endm
    



    .data
    .balign 64
round_constants:
    .quad 0x0000000000000001
    .quad 0x0000000000008082
    .quad 0x800000000000808a
    .quad 0x8000000080008000
    .quad 0x000000000000808b
    .quad 0x0000000080000001
    .quad 0x8000000080008081
    .quad 0x8000000000008009
    .quad 0x000000000000008a
    .quad 0x0000000000000088
    .quad 0x0000000080008009
    .quad 0x000000008000000a
    .quad 0x000000008000808b
    .quad 0x800000000000008b
    .quad 0x8000000000008089
    .quad 0x8000000000008003
    .quad 0x8000000000008002
    .quad 0x8000000000000080
    .quad 0x000000000000800a
    .quad 0x800000008000000a
    .quad 0x8000000080008081
    .quad 0x8000000000008080
    .quad 0x0000000080000001
    .quad 0x8000000080008008


str_ptr  .req X29    //store the input pointer
round   .req X30    //store the round number



/* Iota
    instructions: 2
    avg throughput: 3
    estimated expected cycles: 7
    estimated time @ 1.8ghz: 7*0.556 = 3.9ns
    estimated total time: 3.9ns * 24 = 93.6ns
*/
.macro iota
    adr x25, round_constants 
    LDR x26, [x25, round, lsl #3]
    EOR L_X0Y0, L_X0Y0, x26
.endm


/* Takes about 38ns and 933ns for 24 rounds */
.macro keccak_round
    theta
    rho_pi
    chi
    iota
.endm


// AAPCS64 
.macro callee_saved
    STP X19, X20, [SP, #-16]!
    STP X21, X22, [SP, #-16]!
    STP X23, X24, [SP, #-16]!
    STP X25, X26, [SP, #-16]!
    STP X27, X28, [SP, #-16]!
    STP X29, X30, [SP, #-16]!
.endm

// AAPCS64
.macro callee_restored
    LDP X29, X30, [SP], #16
    LDP X27, X28, [SP], #16
    LDP X25, X26, [SP], #16
    LDP X23, X24, [SP], #16
    LDP X21, X22, [SP], #16
    LDP X19, X20, [SP], #16
.endm



.text
.balign 32
.global KeccakF1600_StatePermute_ARMv8A
.type KeccakF1600_StatePermute_ARMv8A, %function



// X0: address of input
// X1: address of output
KeccakF1600_StatePermute_ARMv8A:
    // Procedure call convention
    callee_saved

    // Move the addresses
    MOV str_ptr, X0 

    // Set the round number to 0
    MOV round, #0

    // Load the string into state array i.e. X0 to X24
    /*
    LDP L_X0Y0, L_X0Y1, [str_ptr, #0]
    LDP L_X0Y2, L_X0Y3, [str_ptr, #16]
    LDP L_X0Y4, L_X1Y0, [str_ptr, #32]
    LDP L_X1Y1, L_X1Y2, [str_ptr, #48]
    LDP L_X1Y3, L_X1Y4, [str_ptr, #64]
    LDP L_X2Y0, L_X2Y1, [str_ptr, #80]
    LDP L_X2Y2, L_X2Y3, [str_ptr, #96]
    LDP L_X2Y4, L_X3Y0, [str_ptr, #112]
    LDP L_X3Y1, L_X3Y2, [str_ptr, #128]
    LDP L_X3Y3, L_X3Y4, [str_ptr, #144]
    LDP L_X4Y0, L_X4Y1, [str_ptr, #160]
    LDP L_X4Y2, L_X4Y3, [str_ptr, #176]
    LDR L_X4Y4, [str_ptr, #192]
    */

    LDP L_X0Y0, L_X1Y0, [str_ptr, #0]
    LDP L_X2Y0, L_X3Y0, [str_ptr, #16]
    LDP L_X4Y0, L_X0Y1, [str_ptr, #32]
    LDP L_X1Y1, L_X2Y1, [str_ptr, #48]
    LDP L_X3Y1, L_X4Y1, [str_ptr, #64]
    LDP L_X0Y2, L_X1Y2, [str_ptr, #80]
    LDP L_X2Y2, L_X3Y2, [str_ptr, #96]
    LDP L_X4Y2, L_X0Y3, [str_ptr, #112]
    LDP L_X1Y3, L_X2Y3, [str_ptr, #128]
    LDP L_X3Y3, L_X4Y3, [str_ptr, #144]
    LDP L_X0Y4, L_X1Y4, [str_ptr, #160]
    LDP L_X2Y4, L_X3Y4, [str_ptr, #176]
    LDR L_X4Y4, [str_ptr, #192]



    // loop over all the rounds
loop:
    keccak_round
    add round, round, #1
    cmp round, #23        // 24 rounds
    ble loop

    // Store the state back to memory
    /*
    STP L_X0Y0, L_X0Y1, [str_ptr, #0]
    STP L_X0Y2, L_X0Y3, [str_ptr, #16]
    STP L_X0Y4, L_X1Y0, [str_ptr, #32]
    STP L_X1Y1, L_X1Y2, [str_ptr, #48]
    STP L_X1Y3, L_X1Y4, [str_ptr, #64]
    STP L_X2Y0, L_X2Y1, [str_ptr, #80]
    STP L_X2Y2, L_X2Y3, [str_ptr, #96]
    STP L_X2Y4, L_X3Y0, [str_ptr, #112]
    STP L_X3Y1, L_X3Y2, [str_ptr, #128]
    STP L_X3Y3, L_X3Y4, [str_ptr, #144]
    STP L_X4Y0, L_X4Y1, [str_ptr, #160]
    STP L_X4Y2, L_X4Y3, [str_ptr, #176]
    STR L_X4Y4, [str_ptr, #192]
    */

    STP L_X0Y0, L_X1Y0, [str_ptr, #0]
    STP L_X2Y0, L_X3Y0, [str_ptr, #16]
    STP L_X4Y0, L_X0Y1, [str_ptr, #32]
    STP L_X1Y1, L_X2Y1, [str_ptr, #48]
    STP L_X3Y1, L_X4Y1, [str_ptr, #64]
    STP L_X0Y2, L_X1Y2, [str_ptr, #80]
    STP L_X2Y2, L_X3Y2, [str_ptr, #96]
    STP L_X4Y2, L_X0Y3, [str_ptr, #112]
    STP L_X1Y3, L_X2Y3, [str_ptr, #128]
    STP L_X3Y3, L_X4Y3, [str_ptr, #144]
    STP L_X0Y4, L_X1Y4, [str_ptr, #160]
    STP L_X2Y4, L_X3Y4, [str_ptr, #176]
    STR L_X4Y4, [str_ptr, #192]

    // Procedure call convention
    callee_restored

    // Return
    RET

//keccak_round
