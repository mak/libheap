################################################################################
# MALLOC CONSTANTS AND MACROS
################################################################################

try:
    import gdb
except ImportError:
    print "Not running inside of GDB, exiting..."
    exit()


import sys
import struct



# HEAPFILE = os.path.abspath(os.path.expanduser(__file__))
# if os.path.islink(HEAPFILE):
#     HEAPFILE = os.readlink(HEAPFILE)
# sys.path.append(os.path.dirname(HEAPFILE))

from util import *


_machine = uname()[4]
SIZE_SZ = gdb.lookup_type('int').pointer().sizeof

MIN_CHUNK_SIZE    = 4 * SIZE_SZ
MALLOC_ALIGNMENT  = 2 * SIZE_SZ
MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1
MINSIZE           = (MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK

def chunk2mem(p):
    "conversion from malloc header to user pointer"
    return (p.address + (2*SIZE_SZ))

def mem2chunk(mem):
    "conversion from user pointer to malloc header"
    return (mem - (2*SIZE_SZ))

def request2size(req):
    "pad request bytes into a usable size"

    if (req + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE):
        return MINSIZE
    else:
        return ((req + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

PREV_INUSE     = 1
IS_MMAPPED     = 2
NON_MAIN_ARENA = 4
SIZE_BITS      = (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)

def prev_inuse(p):
    "extract inuse bit of previous chunk"
    return (p.size & PREV_INUSE)

def chunk_is_mmapped(p):
    "check for mmap()'ed chunk"
    return (p.size & IS_MMAPPED)

def chunk_non_main_arena(p):
    "check for chunk from non-main arena"
    return (p.size & NON_MAIN_ARENA)

def chunksize(p):
    "Get size, ignoring use bits"
    return (p.size & ~SIZE_BITS)

def next_chunk(p):
    "Ptr to next physical malloc_chunk."
    return (p.address + (p.size & ~SIZE_BITS))

def prev_chunk(p):
    "Ptr to previous physical malloc_chunk"
    return (p.address - p.prev_size)

def chunk_at_offset(p, s):
    "Treat space at ptr + offset as a chunk"
    return malloc_chunk(p.address + s, inuse=False)

def inuse(p):
    "extract p's inuse bit"
    return (malloc_chunk(p.address + \
            (p.size & ~SIZE_BITS), inuse=False).size & PREV_INUSE)

def set_inuse(p):
    "set chunk as being inuse without otherwise disturbing"
    chunk = malloc_chunk((p.address + (p.size & ~SIZE_BITS)), inuse=False)
    chunk.size |= PREV_INUSE
    chunk.write()

def clear_inuse(p):
    "clear chunk as being inuse without otherwise disturbing"
    chunk = malloc_chunk((p.address + (p.size & ~SIZE_BITS)), inuse=False)
    chunk.size &= ~PREV_INUSE
    chunk.write()

def inuse_bit_at_offset(p, s):
    "check inuse bits in known places"
    return (malloc_chunk((p.address + s), inuse=False).size & PREV_INUSE)

def set_inuse_bit_at_offset(p, s):
    "set inuse bits in known places"
    chunk = malloc_chunk((p.address + s), inuse=False)
    chunk.size |= PREV_INUSE
    chunk.write()

def clear_inuse_bit_at_offset(p, s):
    "clear inuse bits in known places"
    chunk = malloc_chunk((p.address + s), inuse=False)
    chunk.size &= ~PREV_INUSE
    chunk.write()

def bin_at(m, i):
    "addressing -- note that bin_at(0) does not exist"
    if SIZE_SZ == 4:
        offsetof_fd = 0x8

    elif SIZE_SZ == 8:
        offsetof_fd = 0x10

    return m.address + m.bins_off + (((i -1) * 2)*4) - offsetof_fd

def next_bin(b):
    return (b + 1)

def first(b):
    return b.fd

def last(b):
    return b.bk

NBINS          = 128
NSMALLBINS     = 64
SMALLBIN_WIDTH = MALLOC_ALIGNMENT
MIN_LARGE_SIZE = (NSMALLBINS * SMALLBIN_WIDTH)

def in_smallbin_range(sz):
    "check if size is in smallbin range"
    return (sz < MIN_LARGE_SIZE)

def smallbin_index(sz):
    "return the smallbin index"

    if SMALLBIN_WIDTH == 16:
        return (sz >> 4)
    else:
        return (sz >> 3)

def largebin_index_32(sz):
    "return the 32bit largebin index"

    if (sz >> 6) <= 38:
        return (56 + (sz >> 6))
    elif (sz >> 9) <= 20:
        return (91 + (sz >> 9))
    elif (sz >> 12) <= 10:
        return (110 + (sz >> 12))
    elif (sz >> 15) <= 4:
        return (119 + (sz >> 15))
    elif (sz >> 18) <= 2:
        return (124 + (sz >> 18))
    else:
        return 126

def largebin_index_64(sz):
    "return the 64bit largebin index"

    if (sz >> 6) <= 48:
        return (48 + (sz >> 6))
    elif (sz >> 9) <= 20:
        return (91 + (sz >> 9))
    elif (sz >> 12) <= 10:
        return (110 + (sz >> 12))
    elif (sz >> 15) <= 4:
        return (119 + (sz >> 15))
    elif (sz >> 18) <= 2:
        return (124 + (sz >> 18))
    else:
        return 126

def largebin_index(sz):
    "return the largebin index"

    if SIZE_SZ == 8:
        return largebin_index_64(sz)
    else:
        return largebin_index_32(sz)

def bin_index(sz):
    "return the bin index"

    if in_smallbin_range(sz):
        return smallbin_index(sz)
    else:
        return largebin_index(sz)

BINMAPSHIFT = 5
BITSPERMAP  = 1 << BINMAPSHIFT
BINMAPSIZE  = (NBINS / BITSPERMAP)

def fastbin(ar_ptr, idx):
    return ar_ptr.fastbinsY[idx]

def fastbin_index(sz):
    "offset 2 to use otherwise unindexable first 2 bins"
    if SIZE_SZ == 8:
        return ((sz >> 4) - 2)
    else:
        return ((sz >> 3) - 2)

MAX_FAST_SIZE = (80 * SIZE_SZ / 4)
NFASTBINS     = (fastbin_index(request2size(MAX_FAST_SIZE)) + 1)

FASTCHUNKS_BIT = 0x1

def have_fastchunks(M):
    return ((M.flags & FASTCHUNKS_BIT) == 0)

def clear_fastchunks(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags |= FASTCHUNKS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

def set_fastchunks(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags &= ~FASTCHUNKS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

NONCONTIGUOUS_BIT = 0x2

def contiguous(M):
    return ((M.flags & NONCONTIGUOUS_BIT) == 0)

def noncontiguous(M):
    return ((M.flags & NONCONTIGUOUS_BIT) != 0)

def set_noncontiguous(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags |= NONCONTIGUOUS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

def set_contiguous(M, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    M.flags &= ~NONCONTIGUOUS_BIT
    inferior.write_memory(M.address, struct.pack("<I", M.flags))

def get_max_fast():
    return gdb.parse_and_eval("global_max_fast")

def mutex_lock(ar_ptr, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    ar_ptr.mutex = 1
    inferior.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))

def mutex_unlock(ar_ptr, inferior=None):
    if inferior == None:
        inferior = get_inferior()

    ar_ptr.mutex = 0
    inferior.write_memory(ar_ptr.address, struct.pack("<I", ar_ptr.mutex))



################################################################################
class malloc_chunk:
    "python representation of a struct malloc_chunk"

    def __init__(self,addr=None,mem=None,size=None,inferior=None,inuse=False,read_data=True):
        self.prev_size   = 0
        self.size        = 0
        self.data        = None
        self.fd          = None
        self.bk          = None
        self.fd_nextsize = None
        self.bk_nextsize = None

        if addr == None or addr == 0:
            if mem == None:
                error("Please specify a valid struct malloc_chunk address.")
            self.address = None
        else:
            self.address = addr if type(addr) == int else from_ptr(addr)

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

################################################################################
class malloc_state:
    "python representation of a struct malloc_state"

    def __init__(self, addr=None, mem=None, inferior=None):
        self.mutex          = 0
        self.flags          = 0
        self.fastbinsY      = 0
        self.top            = 0
        self.last_remainder = 0
        self.bins           = 0
        self.binmap         = 0
        self.next           = 0
        self.next_free      = 0 # PER_THREAD shit
        self.system_mem     = 0
        self.max_system_mem = 0

        self.bins_off = 0x38 if SIZE_SZ == 4 else 0x68

        if addr == None:
            if mem == None:
                error("Please specify a struct malloc_state address.")


            self.address = None
        else:
            self.address = addr if type(addr) == int else from_ptr(addr)

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x450)
                elif SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x888)
            except TypeError:
                error("Invalid address specified.")

            except RuntimeError:
                error("Could not read address 0x%x" % addr + c_none)

        if SIZE_SZ == 4:
            (self.mutex,         \
            self.flags)          = struct.unpack_from("<II", mem, 0x0)
            self.fastbinsY       = struct.unpack_from("<10I", mem, 0x8)
            (self.top,           \
            self.last_remainder) = struct.unpack_from("<II", mem, 0x30)

            self.bins            = struct.unpack_from("<254I", mem, 0x38)
            self.binmap          = struct.unpack_from("<IIII", mem, 0x430)
            (self.next,          \
            self.next_free,      \
            self.system_mem,     \
            self.max_system_mem) = struct.unpack_from("<IIII", mem, 0x440)
        elif SIZE_SZ == 8:
            (self.mutex,         \
            self.flags)          = struct.unpack_from("<II", mem, 0x0)
            self.fastbinsY       = struct.unpack_from("<10Q", mem, 0x8)
            (self.top,           \
            self.last_remainder) = struct.unpack_from("<QQ", mem, 0x58)
            self.bins            = struct.unpack_from("<254Q", mem, 0x68)
            self.binmap          = struct.unpack_from("<IIII", mem, 0x858)
            (self.next,          \
            self.next_free,      \
            self.system_mem,     \
            self.max_system_mem) = struct.unpack_from("<QQQQ", mem, 0x868)

    def write(self, inferior=None):
        if inferior == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if SIZE_SZ == 4:
            mem = struct.pack("<275I", self.mutex, self.flags, self.fastbinsY, \
                    self.top, self.last_remainder, self.bins, self.binmap, \
                    self.next, self.system_mem, self.max_system_mem)
        elif SIZE_SZ == 8:
            mem = struct.pack("<II266QIIIIQQQ", self.mutex, self.flags, \
                    self.fastbinsY, self.top, self.last_remainder, self.bins, \
                    self.binmap, self.next, self.system_mem, \
                    self.max_system_mem)

        inferior.write_memory(self.address, mem)

    def __str__(self):
        return "%s%s%x%s%x%s%s%lx%s%lx%s%s%s%lx%s%lx%s%lx%s%lx%s" %      \
                (c_title + "struct malloc_state {",                 \
                c_none + "\nmutex          = " + c_value + "0x",    \
                self.mutex,                                         \
                c_none + "\nflags          = " + c_value + "0x",    \
                self.flags,                                         \
                c_none + "\nfastbinsY      = " + c_value + "{...}", \
                c_none + "\ntop            = " + c_value + "0x",    \
                self.top,                                           \
                c_none + "\nlast_remainder = " + c_value + "0x",    \
                self.last_remainder,                                \
                c_none + "\nbins           = " + c_value + "{...}", \
                c_none + "\nbinmap         = " + c_value + "{...}", \
                c_none + "\nnext           = " + c_value + "0x",    \
                self.next,                                          \
                c_none + "\nnext_free      = " + c_value + "0x",    \
                self.next_free,                                     \
                c_none + "\nsystem_mem     = " + c_value + "0x",    \
                self.system_mem,                                    \
                c_none + "\nmax_system_mem = " + c_value + "0x",    \
                self.max_system_mem, c_none)


################################################################################
class malloc_par:
    "python representation of a struct malloc_par"

    def __init__(self, addr=None, mem=None, inferior=None):
        self.trim_threshold   = 0
        self.top_pad          = 0
        self.mmap_threshold   = 0
        self.arena_test       = 0
        self.arena_max        = 0
        self.n_mmaps          = 0
        self.n_mmaps_max      = 0
        self.max_n_mmaps      = 0
        self.no_dyn_threshold = 0
        #self.pagesize         = 0
        self.mmapped_mem      = 0
        self.max_mmapped_mem  = 0
        self.max_total_mem    = 0
        self.sbrk_base        = 0

        if addr == None:
            if mem == None:
                error("Please specify a struct malloc_par address.")

            self.address = None
        else:
            self.address = addr if type(addr) == int else from_ptr(addr)

        if inferior == None and mem == None:
            inferior = get_inferior()
            if inferior == -1:
                return None

        if mem == None:
            # a string of raw memory was not provided
            try:
                if SIZE_SZ == 4:
                    mem = inferior.read_memory(addr, 0x34)
                elif SIZE_SZ == 8:
                    mem = inferior.read_memory(addr, 0x68)
            except TypeError:
                error("Invalid address specified.")


            except RuntimeError:
                error("Could not read address 0x%x" % addr)

        if SIZE_SZ == 4:
            (self.trim_threshold, \
            self.top_pad,         \
            self.mmap_threshold,  \
            self.arena_test,      \
            self.arena_max,       \
            self.n_mmaps,         \
            self.n_mmaps_max,     \
            self.max_n_mmaps,     \
            self.no_dyn_threshold,\
            #self.pagesize,        \
            self.mmapped_mem,     \
            self.max_mmapped_mem, \
            self.max_total_mem,   \
            self.sbrk_base)       = struct.unpack("<13I", mem)
        elif SIZE_SZ == 8:
            (self.trim_threshold, \
            self.top_pad,         \
            self.mmap_threshold,  \
            self.arena_test,      \
            self.arena_max,       \
            self.n_mmaps,         \
            self.n_mmaps_max,     \
            self.max_n_mmaps,     \
            self.no_dyn_threshold,\
            #self.pagesize,        \
            self.mmapped_mem,     \
            self.max_mmapped_mem, \
            self.max_total_mem,   \
            self.sbrk_base)       = struct.unpack("<13Q", mem)

    def __str__(self):
        return "%s%s%lx%s%lx%s%lx%s%x%s%x%s%x%s%x%s%x%s%lx%s%lx%s%lx%s%lx%s" % \
                (c_title + "struct malloc_par {",                  \
                c_none + "\ntrim_threshold   = " + c_value + "0x", \
                self.trim_threshold,                               \
                c_none + "\ntop_pad          = " + c_value + "0x", \
                self.top_pad,                                      \
                c_none + "\nmmap_threshold   = " + c_value + "0x", \
                self.mmap_threshold,                               \
                c_none + "\nn_mmaps          = " + c_value + "0x", \
                self.n_mmaps,                                      \
                c_none + "\nn_mmaps_max      = " + c_value + "0x", \
                self.n_mmaps_max,                                  \
                c_none + "\nmax_n_mmaps      = " + c_value + "0x", \
                self.max_n_mmaps,                                  \
                c_none + "\nno_dyn_threshold = " + c_value + "0x", \
                self.no_dyn_threshold,                             \
                c_none + "\npagesize         = " + c_value + "0x", \
                self.pagesize,                                     \
                c_none + "\nmmapped_mem      = " + c_value + "0x", \
                self.mmapped_mem,                                  \
                c_none + "\nmax_mmapped_mem  = " + c_value + "0x", \
                self.max_mmapped_mem,                              \
                c_none + "\nmax_total_mem    = " + c_value + "0x", \
                self.max_total_mem,                                \
                c_none + "\nsbrk_base        = " + c_value + "0x", \
                self.sbrk_base,                                    \
                c_none)



################################################################################
# ARENA CONSTANTS AND MACROS
################################################################################
HEAP_MIN_SIZE     = 32 * 1024
HEAP_MAX_SIZE     = 1024 * 1024

def top(ar_ptr):
    return ar_ptr.top

def heap_for_ptr(ptr):
    "find the heap and corresponding arena for a given ptr"
    return (ptr & ~(HEAP_MAX_SIZE-1))
