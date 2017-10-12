# OneRing
The exploit achieves R/W access to the host's physical memory. The password for the archive is "one_ring".

This exploit has been tested on the iPhone 7, iOS 10.2 (14C92). To run the exploit against different devices or versions, the symbols must be adjusted.

The attached archive contains the following directories: <br>
  - hostapd-2.6 : A modified version of hostapd utilised in the exploit. This version of hostapd is configured to
                 support 802.11k RRM, and in particular Neighbor Reports. Moreover, this version of hostapd is
                 instrumented to add various commands, allowing injection and reception of crafted action frames
                 used throughout the exploit.
  - OneRing :     The exploit itself.

  - parse_dt.py : device tree parser Python script
  
To run the exploit, you must execute the following steps:
  - Connect (and enable) a SoftMAC Wi-Fi dongle to your machine (such as the TL-WN722N)
  - Compile the provided version of hostapd
  - Modify the "interface" setting under "hostapd-2.6/hostapd/hostapd.conf" to match your interface's name
  - Configure the following settings under "OneRing/rrm_exploit/conf.py":
    - HOSTAPD_DIR - The directory of the hostapd binary compiled above
    - TARGET_MAC  - The MAC address of the device being exploited
    - AP_MAC      - The MAC address of your wireless dongle
    - INTERFACE   - The name of the wireless dongle's interface
  - Configure the following settings under "OneRing/conf.py":
    - TARGET_MAC  - The MAC address of the device being exploited
    - TARGET_IP   - The IP address of the device being exploited
  - Assemble the backdoor shellcode by running "OneRing/rrm_exploit/assemble_backdoor.sh"
  - Assemble each of the code chunks under "OneRing/code_chunks" by running "compile.sh"
  - Run hostapd with the configuration file provided above, broadcasting a Wi-Fi network ("test80211k")
  - Connect the target device to the network
  - Run "OneRing/attack.py"

Following the steps above should result in DART's descriptor being mapped into IO-Space, allowing R/W access to the host's physical memory. You can utilise this R/W access by calling the "read_host_dword" and "write_host_dword" functions, respectively.


- [Over The Air - Vol. 2, Pt. 1: Exploiting The Wi-Fi Stack on Apple Devices](https://googleprojectzero.blogspot.fr/2017/09/over-air-vol-2-pt-1-exploiting-wi-fi.html?m=1) 
- [Over The Air - Vol. 2, Pt. 2: Exploiting The Wi-Fi Stack on Apple Devices](https://googleprojectzero.blogspot.fr/2017/10/over-air-vol-2-pt-2-exploiting-wi-fi.html?m=1) 
- [Over The Air - Vol. 2, Pt. 3: Exploiting The Wi-Fi Stack on Apple Devices](https://googleprojectzero.blogspot.fr/2017/10/over-air-vol-2-pt-3-exploiting-wi-fi.html?m=1)



All credits go to (afaik) [laginimaineb](https://twitter.com/laginimaineb) of Google Project Zero
