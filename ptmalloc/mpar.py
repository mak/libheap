import gdb,struct
from util import *

SIZE_SZ = gdb.lookup_type('int').pointer().sizeof
################################################################################
class malloc_par:
    "python representation of a struct malloc_par"


    def __init__(self,addr,**args):
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

        if 'addr' in args:
            del args['addr']
        self.read(addr=addr,**args)

    def read(self, addr=None, mem=None, inferior=None):

        if addr == None:
            if mem == None:
                error("Please specify a struct malloc_par address.")

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
        return self.dump()

    def dump(self):
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
