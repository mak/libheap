import gdb,struct
from util import *

#import mbin,mchunk,mfastbin
#import

SIZE_SZ = gdb.lookup_type('int').pointer().sizeof
NONCONTIGUOUS_BIT = 0x2

ptrfmt = 'I' if SIZE_SZ == 4 else 'Q'


################################################################################
class malloc_state:
    "python representation of a struct malloc_state"

    def __init__(self,addr,**args):
        self.mutex          = 0
        self.flags          = 0
        self.fastbinsY      = []
        self.top            = 0
        self.last_remainder = 0
        self.bins           = []
        self.binmap         = 0 ## should be array?
        self.next           = 0
        self.next_free      = 0 # PER_THREAD shit
        self.system_mem     = 0
        self.max_system_mem = 0
        self.bins_off = 0x38 if SIZE_SZ == 4 else 0x68

        if 'addr' in args:
            del args['addr']

        self.read(addr=addr,**args)

    def read(self, addr=None, mem=None, inferior=None):

        if addr == None:
            if mem == None:
                error("Please specify a struct malloc_state address.")


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
            # fastbins -- struct.unpack_from("<10I", mem, 0x8)
            self.fastbinsY       = self.read_fastbins(mem)
            (self.top,           \
            self.last_remainder) = struct.unpack_from("<II", mem, 0x30)
            # bins -- struct.unpack_from("<254I", mem, 0x38)
            self.bins            = self.read_bins(mem)
            self.binmap          = struct.unpack_from("<IIII", mem, 0x430)
            (self.next,          \
            self.next_free,      \
            self.system_mem,     \
            self.max_system_mem) = struct.unpack_from("<IIII", mem, 0x440)
        elif SIZE_SZ == 8:
            (self.mutex,         \
            self.flags)          = struct.unpack_from("<II", mem, 0x0)
            #fastbins -- struct.unpack_from("<10Q", mem, 0x8)
            self.fastbinsY       = self.read_fastbins(mem)
            (self.top,           \
            self.last_remainder) = struct.unpack_from("<QQ", mem, 0x58)
            #bins -- struct.unpack_from("<254Q", mem, 0x68)
            self.bins            = self.read_bins(mem)
            self.binmap          = struct.unpack_from("<IIII", mem, 0x858)
            (self.next,          \
            self.next_free,      \
            self.system_mem,     \
            self.max_system_mem) = struct.unpack_from("<QQQQ", mem, 0x868)


    def read_bins(self,mem):
        size = 0x38 if SIZE_SZ == 4 else 0x68
        bins = struct.unpack_from('<254%s'%ptrfmt,mem,size)
        return bins
        #,self)) for b in bins]

    def read_fastbins(self,mem):
        fbins = struct.unpack_from('<10%s'%ptrfmt,mem,0x8)
        return fbins
        #[malloc_fastbin(b,self) for fb in fbins]

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
        return self.dump()

    def dump(self):
        return "%s%s%x%s%x%s%s%lx%s%lx%s%s%s%lx%s%lx%s%lx%s%lx%s" %      \
                (c_title + "struct malloc_state @(%lx) {"%self.address,  \
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

    def bin_at(self, i):
        "addressing -- note that bin_at(0) does not exist"
        if SIZE_SZ == 4:
            offsetof_fd = 0x8

        elif SIZE_SZ == 8:
            offsetof_fd = 0x10

        return self.address + self.bins_off + (((i -1) * 2)*SIZE_SZ) - offsetof_fd


    def contiguous(self):
        return ((self.flags & NONCONTIGUOUS_BIT) == 0)

    def noncontiguous(self):
        return ((self.flags & NONCONTIGUOUS_BIT) != 0)

    def set_noncontiguous(self, inferior=None):
        if inferior == None:
            inferior = get_inferior()
        self.flags |= NONCONTIGUOUS_BIT
        inferior.write_memory(self.address, struct.pack("<I", self.flags))

    def set_contiguous(self, inferior=None):
        if inferior == None:
            inferior = get_inferior()

        self.flags &= ~NONCONTIGUOUS_BIT
        inferior.write_memory(self.address, struct.pack("<I", self.flags))

    def mutex_lock(self, inferior=None):
        if inferior == None:
            inferior = get_inferior()

        self.mutex = 1
        inferior.write_memory(ar_ptr.address, struct.pack("<I", self.mutex))

    def mutex_unlock(self, inferior=None):
        if inferior == None:
            inferior = get_inferior()

        self.mutex = 0
        inferior.write_memory(self.address, struct.pack("<I", self.mutex))

    def have_fastchunks(self):
        return ((self.flags & FASTCHUNKS_BIT) == 0)

    def clear_fastchunks(self, inferior=None):
        if inferior == None:
            inferior = get_inferior()

        self.flags |= FASTCHUNKS_BIT
        inferior.write_memory(self.address, struct.pack("<I", self.flags))

    def set_fastchunks(self, inferior=None):
        if inferior == None:
            inferior = get_inferior()

        self.flags &= ~FASTCHUNKS_BIT
        inferior.write_memory(self.address, struct.pack("<I", self.flags))
