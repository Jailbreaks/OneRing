arm-linux-androideabi-as chunk.S -o chunk.o
arm-linux-androideabi-objcopy -O binary chunk.o chunk.bin
arm-linux-androideabi-objdump -D chunk.o
