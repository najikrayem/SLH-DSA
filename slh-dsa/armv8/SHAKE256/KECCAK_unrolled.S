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

.text
.balign 64

theta:

    EOR C_X0, L_X0Y0, L_X0Y1
    EOR C_X1, L_X1Y0, L_X1Y1
    STP X29, X30, [SP, #-16]!   //impostor
    EOR C_X2, L_X2Y0, L_X2Y1
    EOR C_X3, L_X3Y0, L_X3Y1
    EOR C_X4, L_X4Y0, L_X4Y1

    EOR C_X0, C_X0, L_X0Y2
    EOR C_X1, C_X1, L_X1Y2
    EOR C_X2, C_X2, L_X2Y2
    EOR C_X3, C_X3, L_X3Y2
    EOR C_X4, C_X4, L_X4Y2

    EOR C_X0, C_X0, L_X0Y3
    EOR C_X1, C_X1, L_X1Y3
    EOR C_X2, C_X2, L_X2Y3
    EOR C_X3, C_X3, L_X3Y3
    EOR C_X4, C_X4, L_X4Y3

    EOR C_X0, C_X0, L_X0Y4
    EOR C_X1, C_X1, L_X1Y4
    EOR C_X2, C_X2, L_X2Y4
    EOR C_X3, C_X3, L_X3Y4
    EOR C_X4, C_X4, L_X4Y4

    /* Calculate 'D' and store it in X25-x28 and X30 */
    EOR D_X0, C_X4, C_X1, ROR #63        // C_X1: 1, C_X4: 1
    EOR D_X2, C_X1, C_X3, ROR #63        // C_X1: *, C_X3: 1, C_X4: 1
    EOR D_X4, C_X3, C_X0, ROR #63        // C_X0: 1, C_X3: *, C_X4: 1
    EOR D_X1, C_X0, C_X2, ROR #63        // C_X0: *, C_X2: 1, C_X4: 1
    EOR D_X3, C_X2, C_X4, ROR #63        // C_X2: *, C_X4: *

    /* XOR all lanes with respective 'D' */
    EOR L_X0Y0, L_X0Y0, D_X0
    EOR L_X1Y0, L_X1Y0, D_X1
    EOR L_X2Y0, L_X2Y0, D_X2
    EOR L_X3Y0, L_X3Y0, D_X3
    EOR L_X4Y0, L_X4Y0, D_X4

    EOR L_X0Y1, L_X0Y1, D_X0
    EOR L_X1Y1, L_X1Y1, D_X1
    EOR L_X2Y1, L_X2Y1, D_X2
    EOR L_X3Y1, L_X3Y1, D_X3
    EOR L_X4Y1, L_X4Y1, D_X4

    EOR L_X0Y2, L_X0Y2, D_X0
    EOR L_X1Y2, L_X1Y2, D_X1
    EOR L_X2Y2, L_X2Y2, D_X2
    EOR L_X3Y2, L_X3Y2, D_X3
    EOR L_X4Y2, L_X4Y2, D_X4

    EOR L_X0Y3, L_X0Y3, D_X0
    EOR L_X1Y3, L_X1Y3, D_X1
    EOR L_X2Y3, L_X2Y3, D_X2
    EOR L_X3Y3, L_X3Y3, D_X3
    EOR L_X4Y3, L_X4Y3, D_X4

    EOR L_X0Y4, L_X0Y4, D_X0
    EOR L_X1Y4, L_X1Y4, D_X1
    EOR L_X2Y4, L_X2Y4, D_X2
    EOR L_X3Y4, L_X3Y4, D_X3
    EOR L_X4Y4, L_X4Y4, D_X4

    LDP X29, X30, [SP], #16

//.endm
    //B rho_pi

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

rho_pi:
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
//.endm
    //B chi

chi:

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

//.endm
    //B iota
    
str_ptr  .req X29    //store the input pointer
round   .req X30    //store the round number

iota:
    adr x25, round_constants 
    LDR x26, [x25, round, lsl #3]
    EOR L_X0Y0, L_X0Y0, x26
//.endm
    B keccak_round_end


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
    //STP X29, X30, [SP, #-16]!     //These will always be done
.endm

// AAPCS64
.macro callee_restored
    //LDP X29, X30, [SP], #16         //These will always be done
    LDP X27, X28, [SP], #16
    LDP X25, X26, [SP], #16
    LDP X23, X24, [SP], #16
    LDP X21, X22, [SP], #16
    LDP X19, X20, [SP], #16
.endm


.text
.balign 64


// Basically the keccak function without the call conventions
keccak_body:
    // Store the link register to the stack
    STP LR, XZR, [SP, #-16]!

    // Move the addresses
    MOV str_ptr, X0 

    // Set the round number to 0
    MOV round, #0

    // Load the string into state array i.e. X0 to X24
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
keccak_loop:
    //keccak_round
    b theta
keccak_round_end:
    add round, round, #1
    cmp round, #23        // 24 rounds
    ble keccak_loop

    // Store the state back to memory
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

    // Restore the link register
    LDP LR, XZR, [SP], #16
    // Return
    RET
.endm



.global KeccakF1600_StatePermute_ARMv8A
.type KeccakF1600_StatePermute_ARMv8A, %function


// X0: address of input
// X1: address of output
KeccakF1600_StatePermute_ARMv8A:
    // Procedure call convention
    callee_saved
    // Store the stack pointer
    STP X29, X30, [SP, #-16]!

    // call the keccak body
    BL keccak_body
    
    // Procedure call convention
    // restore the link pointer
    LDP X29, X30, [SP], #16
    callee_restored

    // Return
    RET
//end






// tmp2   0000 0000     tmp2>>3     0 0000       tmp2>>3     0
// tmp2   0000 0001     tmp2>>3     0 0000       tmp2>>3     0
// tmp2   0000 0010     tmp2>>3     0 0000       tmp2>>3     0
// tmp2   0000 0011     tmp2>>3     0 0000       tmp2>>3     0
// tmp2   0000 0100     tmp2>>3     0 0000       tmp2>>3     0
// tmp2   0000 0101     tmp2>>3     0 0000       tmp2>>3     0
// tmp2   0000 0110     tmp2>>3     0 0000       tmp2>>3     0
// tmp2   0000 0111     tmp2>>3     0 0000       tmp2>>3     0
// tmp2   0000 1000     tmp2>>3     0 0001       tmp2>>3     1
// tmp2   0000 1001     tmp2>>3     0 0001       tmp2>>3     1
// tmp2   0000 1010     tmp2>>3     0 0001       tmp2>>3     1



#define SHAKE256_RATE 136

state_adr   .req X19
msg_adr     .req X20
msg_len     .req X21
tmp         .req X22
tmp2        .req X23
tmp3        .req X24
w_tmp3      .req W24
i           .req X25
state_26    .req X26
scratch1    .req X27
scratch2    .req X28
scratch3    .req X29
scratch4    .req X30
w_scratch4  .req W30

.macro keccak_absorb_inner
    // scratch2 = tmp2 & 0x07
    AND scratch2, tmp2, #0x07

    // scratch1 = (tmp2 >> 3) * 8;
    BIC scratch1, tmp2, #7

    // scratch2 = scratch2 << 3
    LSL scratch2, scratch2, #3

    AND tmp3, scratch4, #0xFF

    // scratch3 = s_inc[scratch1];
    LDR scratch3, [state_adr, scratch1]

    // tmp3 = tmp3 << scratch2;
    LSL tmp3, tmp3, scratch2

    // tmp2++;
    ADD tmp2, tmp2, #1

    // scratch3 = scratch3 ^ tmp3;
    EOR scratch3, scratch3, tmp3

    // s_inc[scratch1] = scratch3;
    STR scratch3, [state_adr, scratch1]
.endm

.macro Keccak_Inc_Absorb_ARMv8A_for_loop_body_X1
    LDRB w_tmp3, [msg_adr, i]
    keccak_absorb_inner

    // i++;
    ADD i, i, #1

.endm

.macro Keccak_Inc_Absorb_ARMv8A_for_loop_body_X2
    LDRH w_scratch4, [msg_adr, i]

    //AND tmp3, scratch4, #0xFF
    keccak_absorb_inner

    LSR tmp3, scratch4, #8
    keccak_absorb_inner

    ADD i, i, #2
.endm

// .macro Keccak_Inc_Absorb_ARMv8A_for_loop_body_X2
//     Keccak_Inc_Absorb_ARMv8A_for_loop_body_X1
//     Keccak_Inc_Absorb_ARMv8A_for_loop_body_X1
// .endm


.macro Keccak_Inc_Absorb_ARMv8A_for_loop_body_X4
    LDR w_scratch4, [msg_adr, i]

    //AND tmp3, scratch4, #0xFF
    keccak_absorb_inner

    //UBFX tmp3, scratch4, #8, #8
    LSR scratch4, scratch4, #8
    keccak_absorb_inner

    //UBFX tmp3, scratch4, #16, #8
    LSR scratch4, scratch4, #8
    keccak_absorb_inner

    //LSR tmp3, scratch4, #24
    LSR scratch4, scratch4, #8
    keccak_absorb_inner

    ADD i, i, #4
.endm


// .macro Keccak_Inc_Absorb_ARMv8A_for_loop_body_X4
//     Keccak_Inc_Absorb_ARMv8A_for_loop_body_X2
//     Keccak_Inc_Absorb_ARMv8A_for_loop_body_X2
// .endm

.macro Keccak_Inc_Absorb_ARMv8A_for_loop_body_X8
    LDR scratch4, [msg_adr, i]

    //AND tmp3, scratch4, #0xFF
    keccak_absorb_inner

    //UBFX tmp3, scratch4, #8, #8
    LSR scratch4, scratch4, #8
    keccak_absorb_inner

    //UBFX tmp3, scratch4, #16, #8
    LSR scratch4, scratch4, #8
    keccak_absorb_inner

    //UBFX tmp3, scratch4, #24, #8
    LSR scratch4, scratch4, #8
    keccak_absorb_inner

    //UBFX tmp3, scratch4, #32, #8
    LSR scratch4, scratch4, #8
    keccak_absorb_inner

    //UBFX tmp3, scratch4, #40, #8
    LSR scratch4, scratch4, #8
    keccak_absorb_inner

    //UBFX tmp3, scratch4, #48, #8
    LSR scratch4, scratch4, #8
    keccak_absorb_inner

    //LSR tmp3, scratch4, #56
    LSR scratch4, scratch4, #8
    keccak_absorb_inner

    ADD i, i, #8
.endm


// .macro Keccak_Inc_Absorb_ARMv8A_for_loop_body_X8
//     Keccak_Inc_Absorb_ARMv8A_for_loop_body_X4
//     Keccak_Inc_Absorb_ARMv8A_for_loop_body_X4
// .endm

.macro Keccak_Inc_Absorb_ARMv8A_for_loop_body_X16
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X8
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X8
.endm

.macro Keccak_Inc_Absorb_ARMv8A_for_loop_body_X32
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X16
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X16
.endm

.macro Keccak_Inc_Absorb_ARMv8A_for_loop_body_X64
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X32
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X32
.endm

.macro Keccak_Inc_Absorb_ARMv8A_for_loop_body, num_itrs, end_label
64:
    // IF (tmp - i) < 64: GOTO x32
    SUBS scratch1, \num_itrs, i  // Subtract i from \num_itrs, result in scratch
    CMP scratch1, #64        // Compare result with 64
    B.LT 32f                 // If result is less than 64, branch
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X64
    B 64b
32: 
    // IF (tmp - i) < 32: GOTO x16
    SUBS scratch1, \num_itrs, i
    CMP scratch1, #32        
    B.LT 16f
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X32
16:
    // IF (tmp - i) < 16: GOTO x8
    SUBS scratch1, \num_itrs, i
    CMP scratch1, #16        
    B.LT 8f
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X16
8:
    // IF (tmp - i) < 8: GOTO x4
    SUBS scratch1, \num_itrs, i
    CMP scratch1, #8        
    B.LT 4f
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X8
4:
    // IF (tmp - i) < 4: GOTO x2
    SUBS scratch1, \num_itrs, i
    CMP scratch1, #4        
    B.LT 2f
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X4
2:
    // IF (tmp - i) < 2: GOTO x1
    SUBS scratch1, \num_itrs, i
    CMP scratch1, #2        
    B.LT 1f
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X2
1:
    // Only iterate if there is at least one more byte to process
    SUBS scratch1, \num_itrs, i
    CMP scratch1, #1
    B.LT \end_label
    Keccak_Inc_Absorb_ARMv8A_for_loop_body_X1
.endm


.global Keccak_Inc_Absorb_ARMv8A
.type Keccak_Inc_Absorb_ARMv8A, %function



// X0: address of input state
// X1: address of input message
// X2: length of input message
Keccak_Inc_Absorb_ARMv8A:
    // Procedure call convention. TODO only needed if used registers 19-30
    callee_saved
    // Store the link register to the stack
    STP x29, x30, [SP, #-16]!

    // move the inputs
    MOV state_adr, X0
    MOV msg_adr, X1
    MOV msg_len, X2

    // Load s_inc[25] into state_26
    LDR state_26, [state_adr, #200]

Keccak_Inc_Absorb_ARMv8A_WL1:
    //while (mlen + s_inc[25] >= SHAKE256_RATE)
    ADD scratch1, msg_len, state_26
    CMP scratch1, #SHAKE256_RATE
    B.LT Keccak_Inc_Absorb_ARMv8A_WL1_END        // TODO

    // tmp = SHAKE256_RATE - s_inc[25];
    MOV tmp, #SHAKE256_RATE
    SUB tmp, tmp, state_26

    // tmp2 = s_inc[25];
    MOV tmp2, state_26

    // for (i = 0; i < tmp; i++)
    MOV i, #0
Keccak_Inc_Absorb_ARMv8A_FL1:
    //CMP i, tmp
    //B.CS Keccak_Inc_Absorb_ARMv8A_FL1_END

    //Keccak_Inc_Absorb_ARMv8A_for_loop_body_X1

    //B Keccak_Inc_Absorb_ARMv8A_FL1

    Keccak_Inc_Absorb_ARMv8A_for_loop_body tmp, Keccak_Inc_Absorb_ARMv8A_FL1_END    

Keccak_Inc_Absorb_ARMv8A_FL1_END:

    // msg_len -= tmp;
    SUB msg_len, msg_len, tmp

    // s_inc[25] = 0;
    MOV state_26, #0

    // msg += tmp;
    ADD msg_adr, msg_adr, tmp


    // permute the state
    MOV x0, state_adr
    STP state_adr, msg_adr, [SP, #-16]!

    MOV x1, state_adr
    STP msg_len, state_26, [SP, #-16]!

    BL keccak_body
    
    LDP msg_len, state_26, [SP], #16
    LDP state_adr, msg_adr, [SP], #16
    
    b Keccak_Inc_Absorb_ARMv8A_WL1


Keccak_Inc_Absorb_ARMv8A_WL1_END:

    // tmp2 = s_inc[25];
    MOV tmp2, state_26

    // for (i = 0; i < msg_len; i++)
    MOV i, #0
Keccak_Inc_Absorb_ARMv8A_FL2:
    // CMP i, msg_len
    // B.CS Keccak_Inc_Absorb_ARMv8A_FL2_END

    // Keccak_Inc_Absorb_ARMv8A_for_loop_body_X1

    // B Keccak_Inc_Absorb_ARMv8A_FL2

    Keccak_Inc_Absorb_ARMv8A_for_loop_body msg_len, Keccak_Inc_Absorb_ARMv8A_FL2_END

Keccak_Inc_Absorb_ARMv8A_FL2_END:
    
    // s_inc[25] += msg_len;
    ADD state_26, state_26, msg_len

    // s_inc[25] = state_26;
    STR state_26, [state_adr, #200]

    // Procedure call convention. TODO only needed if used registers 19-30
    // Restore the link register
    LDP x29, x30, [SP], #16
    callee_restored

    // Return
    RET
     







