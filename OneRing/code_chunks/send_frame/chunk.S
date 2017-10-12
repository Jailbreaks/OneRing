.code 16
  PUSH {R0}
  ADR R0, hook_arm
  BX R0

.code 32
.align 4
hook_arm:
  POP {R0}

  PUSH {R4-R11, LR}

  LDR R11, wlc
 
  //Looping the wanted number of injection repetitions
  LDR R9, num_injections
  MOV R8, #0
loop:
  CMP R8, R9
  BGE ret_zero
 
  //Getting the frame
  LDR R0, [R11, #4]     
  LDR R1, frame_size
  LDR R4, get_frame_func
  BLX R4  
  MOV R10, R0

  //Populating the frame
  LDR R0, [R10, #8]
  ADR R1, frame_contents
  LDR R2, frame_size
  LDR R4, memcpy
  BLX R4 

  //Sending the frame
  LDR R0, [R11, #8]
  MOV R1, #0
  MOV R2, R10
  MOV R3, #1
  LDR R4, send_func
  BLX R4
 
  ADD R8, R8, #1
  B loop

ret_zero:
  //Returning zero
  MOV R0, #0
  POP {R4-R11, PC}

.align 4

wlc:
    .word 0x2058BC

get_frame_func:
    .word 0x70E0+1

send_func:
    .word 0x3E678+1

memcpy:
    .word 0x3DAC+1

num_injections:
    .word 0xBEEFBEEF

frame_size:
    .word 0xF12A515E

frame_contents:
    .space 256,0xAB
