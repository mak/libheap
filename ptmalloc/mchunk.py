
import gdb,struct
from util import *



SIZE_SZ = gdb.lookup_type('int').pointer().sizeof
MIN_CHUNK_SIZE    = 4 * SIZE_SZ
MALLOC_ALIGNMENT  = 2 * SIZE_SZ
MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1
MINSIZE           = (MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK

PREV_INUSE     = 1
IS_MMAPPED     = 2
NON_MAIN_ARENA = 4
SIZE_BITS      = (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)

################################################################################
class malloc_chunk:
    "python representation of a struct malloc_chunk"


    def __init__(self,addr,area=None,**args):
        self.area = area
        self.prev_size   = 0
        self.size        = 0
        self.data        = None
        self.fd          = None
        self.bk          = None
        self.fd_nextsize = None
        self.bk_nextsize = None
        self.address     = addr if isnum(addr) else from_ptr(addr)

        if 'addr' in args:
            del args['addr']

        self.read(addr=addr,**args)

    def read(self,addr=None,mem=None,size=None,inferior=None,inuse=False,read_data=True):

        if addr == None or addr == 0:
            if mem == None:
                error("Please specify a valid struct malloc_chunk address.")
            self.address = None
        else:
            self.address = addr if isnum(addr) else from_ptr(addr)

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x8)
                elif SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x10)

            except TypeError:
                error("Invalid address specified.")

            except RuntimeError:
                error("Could not read address 0x%x" % addr)
        else:
            # a string of raw memory was provided
            if inuse:
                if (len(mem)!=0x8) and (len(mem)<0x10):
                    error("Insufficient memory provided for a malloc_chunk.")

                if len(mem)==0x8 or len(mem)==0x10:
                    #header only provided
                    read_data = False
            else:
                if (len(mem)!=0x18) and (len(mem)<0x30):
                    error("Insufficient memory provided for a free chunk.")

        if SIZE_SZ == 4:
            (self.prev_size,
            self.size) = struct.unpack_from("<II", mem, 0x0)
        elif SIZE_SZ == 8:
            (self.prev_size,
            self.size) = struct.unpack_from("<QQ", mem, 0x0)

        if size == None:
            real_size = (self.size & ~SIZE_BITS)
        else:
            #a size was provided (for a malformed chunk with an invalid size)
            real_size = size & ~SIZE_BITS

        if inuse:
            if read_data:
                if self.address != None:
                    # a string of raw memory was not provided
                    try:
                        mem = inferior.read_memory(addr, real_size + SIZE_SZ)
                    except TypeError:
                        error("Invalid address specified.")

                    except RuntimeError:
                        error("Could not read address 0x%x" % addr)

                real_size = (real_size - SIZE_SZ) / SIZE_SZ
                if SIZE_SZ == 4:
                    self.data = struct.unpack_from("<%dI" % real_size, mem, 0x8)
                elif SIZE_SZ == 8:
                    self.data = struct.unpack_from("<%dQ" %real_size, mem, 0x10)

        if not inuse:
            if self.address != None:
                # a string of raw memory was not provided
                if inferior != None:
                    if SIZE_SZ == 4:
                        mem = inferior.read_memory(addr, 0x18)
                    elif SIZE_SZ == 8:
                        mem = inferior.read_memory(addr, 0x30)

            if SIZE_SZ == 4:
                (self.fd,         \
                self.bk,          \
                self.fd_nextsize, \
                self.bk_nextsize) = struct.unpack_from("<IIII", mem, 0x8)
            elif SIZE_SZ == 8:
                (self.fd,         \
                self.bk,          \
                self.fd_nextsize, \
                self.bk_nextsize) = struct.unpack_from("<QQQQ", mem, 0x10)

    def write(self, inferior=None):
        if self.fd == None and self.bk == None:
            inuse = True
        else:
            inuse = False

        if inferior == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if inuse:
            if SIZE_SZ == 4:
                mem = struct.pack("<II", self.prev_size, self.size)
                if self.data != None:
                    mem += struct.pack("<%dI" % len(self.data), *self.data)
            elif SIZE_SZ == 8:
                mem = struct.pack("<QQ", self.prev_size, self.size)
                if self.data != None:
                    mem += struct.pack("<%dQ" % len(self.data), *self.data)
        else:
            if SIZE_SZ == 4:
                mem = struct.pack("<IIIIII", self.prev_size, self.size, \
                        self.fd, self.bk, self.fd_nextsize, self.bk_nextsize)
            elif SIZE_SZ == 8:
                mem = struct.pack("<QQQQQQ", self.prev_size, self.size, \
                        self.fd, self.bk, self.fd_nextsize, self.bk_nextsize)

        inferior.write_memory(self.address, mem)

    def __str__(self):
        return self.dump()

    def dump(self):
        if self.prev_size == 0 and self.size == 0:
            return ""
        elif self.fd == None and self.bk == None:
            ret =  "%s%s%x%s%x%s" %                               \
                    (c_title + "struct malloc_chunk {",           \
                    c_none + "\nprev_size   = " + c_value + "0x", \
                    self.prev_size,                               \
                    c_none + "\nsize        = " + c_value + "0x", \
                    self.size, c_none)

            if self.data != None:
                if SIZE_SZ == 4:
                    ret += "%s%s%r" %                                       \
                            ("\ndata        = " + c_value + str(self.data), \
                            c_none + "\nraw         = " + c_value,          \
                            struct.pack("<%dI"%len(self.data), *self.data))
                elif SIZE_SZ == 8:
                    ret += "%s%s%r" %                                       \
                            ("\ndata        = " + c_value + str(self.data), \
                            c_none + "\nraw         = " + c_value,          \
                            struct.pack("<%dQ"%len(self.data), *self.data))
                ret += c_none

            return ret
        else:
            return "%s%s%x%s%x%s%lx%s%lx%s%lx%s%lx%s" %           \
                    (c_title + "struct malloc_chunk {",           \
                    c_none + "\nprev_size   = " + c_value + "0x", \
                    self.prev_size,                               \
                    c_none + "\nsize        = " + c_value + "0x", \
                    self.size,                                    \
                    c_none + "\nfd          = " + c_value + "0x", \
                    self.fd,                                      \
                    c_none + "\nbk          = " + c_value + "0x", \
                    self.bk,                                      \
                    c_none + "\nfd_nextsize = " + c_value + "0x", \
                    self.fd_nextsize,                             \
                    c_none + "\nbk_nextsize = " + c_value + "0x", \
                    self.bk_nextsize, c_none)

    def prev_inuse(self):
        "extract inuse bit of previous chunk"
        return (self.size & PREV_INUSE)

    def chunk_is_mmapped(self):
        "check for mmap()'ed chunk"
        return (self.size & IS_MMAPPED)

    def chunk_non_main_arena(self):
        "check for chunk from non-main arena"
        return (self.size & NON_MAIN_ARENA)

    def chunksize(self):
        "Get size, ignoring use bits"
        return (self.size & ~SIZE_BITS)

    def next_chunk(self):
        "Ptr to next physical malloc_chunk."
        return (self.address + (self.size & ~SIZE_BITS))

    def prev_chunk(self):
        "Ptr to previous physical malloc_chunk"
        return (self.address - self.prev_size)

    def inuse(self):
        "extract p's inuse bit"
        self.inuse_bit_at_offset(self.size & ~SIZE_BITS)

    def set_inuse(self):
        "set chunk as being inuse without otherwise disturbing"
        self.set_inuse_bit_at_offset(self.size & ~SIZE_BITS)

    def clear_inuse(self):
        "clear chunk as being inuse without otherwise disturbing"
        self.clear_inuse_bit_at_offset(self.size & ~SIZE_BITS)

    def inuse_bit_at_offset(self, s):
        "check inuse bits in known places"
        return (malloc_chunk((self.address + s)).size & PREV_INUSE)

    def set_inuse_bit_at_offset(self, s):
        "set inuse bits in known places"
        chunk = malloc_chunk(self.address + s)
        chunk.size |= PREV_INUSE
        chunk.write()

    def clear_inuse_bit_at_offset(self, s):
        "clear inuse bits in known places"
        chunk = malloc_chunk(self.address + s)
        chunk.size &= ~PREV_INUSE
        chunk.write()
