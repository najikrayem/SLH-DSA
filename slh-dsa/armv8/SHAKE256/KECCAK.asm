

@ ; Assume X0 is the address of the message

@ ; Load first double word of the message into X1
@ LDR X1, [X0]

@ ; Load second double word of the message into X2
@ LDR X2, [X0, #8]

@ ;xor the two double words
@ EOR X1, X1, X2


; In the AArch64 procedure call standard, the first 8 registers (X0..X7) are used to pass arguments. Registers X0..X15 are corruptable. 


.global keccak
.type keccak, %function


; X0: address of input message
; X1: address of output hash
keccak:

    ; Load the 25 double words of the state into registers X0 to X24
    LDR X0, [X1, #0]
    


