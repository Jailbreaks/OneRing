import sys, struct, string

#The known register fields in the device tree
#These fields are printed as 64-bit little-endian words
REGISTER_FIELDS = ["reg",
                   "error-reflector",
                   "encoding", 
                   "decoding", 
                   "interrupts", 
                   "resource-config", 
                   "reg-private",
                   "acc-impl-tunables"]

#The size of a name entry in the device tree
NAME_SIZE = 0x20

#The size of a DWORD, in bytes
DWORD_SIZE = 4

#The size of a QWORD, in bytes
QWORD_SIZE = 8

#The threshold of unprintable characters, above which a field is considered "binary"
HEX_SUSP_THRESH = 3

#CR, LF, VTAB, FF
NEWLINES = ['\r','\n','\x0c','\x0b']

#The width of a printed line separator
LINE_WIDTH = 100

class FileStream(object):
    '''
    Simple stream abstraction for a data blob
    '''

    def __init__(self, data):
        self.data = data
        self.index = 0

    def read_bytes(self, size):
        buf = self.data[self.index:self.index+size]
        self.index += size
        return buf
    
    def read_dword(self):
        return struct.unpack("<I", self.read_bytes(DWORD_SIZE))[0]

    def has_more(self):
        return self.index < len(self.data)

def parse_node(dt, depth=0):
    '''
    Parses a single node in the device tree
    '''

    num_entries = dt.read_dword()
    num_children = dt.read_dword()

    #Printing all the entries in this node
    for entry_idx in range(num_entries):
        
        name = dt.read_bytes(NAME_SIZE).strip().strip("\x00")
        
        value_size = dt.read_dword() & 0xFFFFFF #Ignoring unknown flags in upper byte
        raw_value = dt.read_bytes(value_size)
        value = "".join(map(lambda x: x if x in string.printable else "<%02X>" % ord(x), raw_value.rstrip("\x00")))

        #Align to a DWORD
        if (value_size % DWORD_SIZE) != 0:
            dt.read_bytes(DWORD_SIZE - (value_size % DWORD_SIZE))
        
        #Is this a known binary field?
        if name in REGISTER_FIELDS:
            value = " ".join(["0x%016X" % struct.unpack("<Q", raw_value[i : i + QWORD_SIZE])[0]
                              for i in range(0, len(raw_value) - QWORD_SIZE + 1, QWORD_SIZE)])

        #Is this a long field with too many binary values (but not a known register field)?
        elif len(filter(lambda x: x != '\x00' and x not in string.printable, raw_value)) > HEX_SUSP_THRESH:
            value = "<%s>" % ("".join(["%02X" % ord(c) for c in raw_value]))

        #Printing the entry
        value = "".join(filter(lambda x: x not in NEWLINES, value))
        print ("    " * depth) + "%-32s %s" % (name, value)

    #Parsing all child nodes
    for i in range(0, num_children):
        print "-" * LINE_WIDTH
        parse_node(dt, depth + 1)


def main():
    if len(sys.argv) != 2:
        print "USAGE: %s <DEVICE_TREE>" % sys.argv[0]
        return

    #Parsing the device tree
    device_tree = FileStream(open(sys.argv[1], "rb").read())
    parse_node(device_tree)

if __name__ == "__main__":
    main()
