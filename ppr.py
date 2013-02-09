
################################################################################
# GDB PRETTY PRINTERS
################################################################################

from ptmalloc import *
from util import *

try:
    import gdb
except ImportError:
    print "Not running inside of GDB, exiting..."
    exit()


class malloc_par_printer:
    "pretty print the malloc parameters (mp_)"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        return "%s%s%lx%s%lx%s%lx%s%x%s%x%s%x%s%x%s%x%s%lx%s%lx%s%lx%s%lx%s" % \
                (c_title + "struct malloc_par {",                  \
                c_none + "\ntrim_threshold   = " + c_value + "0x", \
                self.val['trim_threshold'],                        \
                c_none + "\ntop_pad          = " + c_value + "0x", \
                self.val['top_pad'],                               \
                c_none + "\nmmap_threshold   = " + c_value + "0x", \
                self.val['mmap_threshold'],                        \
                c_none + "\nn_mmaps          = " + c_value + "0x", \
                self.val['n_mmaps'],                               \
                c_none + "\nn_mmaps_max      = " + c_value + "0x", \
                self.val['n_mmaps_max'],                           \
                c_none + "\nmax_n_mmaps      = " + c_value + "0x", \
                self.val['max_n_mmaps'],                           \
                c_none + "\nno_dyn_threshold = " + c_value + "0x", \
                self.val['no_dyn_threshold'],                      \
                c_none + "\npagesize         = " + c_value + "0x", \
                self.val['pagesize'],                              \
                c_none + "\nmmapped_mem      = " + c_value + "0x", \
                self.val['mmapped_mem'],                           \
                c_none + "\nmax_mmapped_mem  = " + c_value + "0x", \
                self.val['max_mmapped_mem'],                       \
                c_none + "\nmax_total_mem    = " + c_value + "0x", \
                self.val['max_total_mem'],                         \
                c_none + "\nsbrk_base        = " + c_value + "0x", \
                self.val['sbrk_base'],                             \
                c_none)

    def display_string(self):
        return "string"

################################################################################
class malloc_state_printer:
    "pretty print a struct malloc_state (ar_ptr)"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        return "%s%s%x%s%x%s%s%lx%s%lx%s%s%s%lx%s%lx%s%lx%s" %      \
                (c_title + "struct malloc_state {",                 \
                c_none + "\nmutex          = " + c_value + "0x",    \
                self.val['mutex'],                                  \
                c_none + "\nflags          = " + c_value + "0x",    \
                self.val['flags'],                                  \
                c_none + "\nfastbinsY      = " + c_value + "{...}", \
                c_none + "\ntop            = " + c_value + "0x",    \
                self.val['top'],                                    \
                c_none + "\nlast_remainder = " + c_value + "0x",    \
                self.val['last_remainder'],                         \
                c_none + "\nbins           = " + c_value + "{...}", \
                c_none + "\nbinmap         = " + c_value + "{...}", \
                c_none + "\nnext           = " + c_value + "0x",    \
                self.val['next'],                                   \
                c_none + "\nsystem_mem     = " + c_value + "0x",    \
                self.val['system_mem'],                             \
                c_none + "\nmax_system_mem = " + c_value + "0x",    \
                self.val['max_system_mem'],                         \
                c_none)

    def display_string(self):
        return "string"

################################################################################
class malloc_chunk_printer:
    "pretty print a struct malloc_chunk"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        return "%s%s%x%s%x%s%lx%s%lx%s%lx%s%lx%s" %           \
                (c_title + "struct malloc_chunk {",           \
                c_none + "\nprev_size   = " + c_value + "0x", \
                self.val['prev_size'],                        \
                c_none + "\nsize        = " + c_value + "0x", \
                self.val['size'],                             \
                c_none + "\nfd          = " + c_value + "0x", \
                self.val['fd'],                               \
                c_none + "\nbk          = " + c_value + "0x", \
                self.val['bk'],                               \
                c_none + "\nfd_nextsize = " + c_value + "0x", \
                self.val['fd_nextsize'],                      \
                c_none + "\nbk_nextsize = " + c_value + "0x", \
                self.val['bk_nextsize'],                      \
                c_none)

    def display_string(self):
        return "string"

################################################################################
class heap_info_printer:
    "pretty print a struct heap_info"

    def __init__(self, val):
        self.val = val

    def to_string(self):
        return "%s%s%lx%s%lx%s%lx%s%lx%s" %                     \
                (c_title + "struct heap_info {",                \
                c_none + "\nar_ptr        = " + c_value + "0x", \
                self.val['ar_ptr'],                             \
                c_none + "\nprev          = " + c_value + "0x", \
                self.val['prev'],                               \
                c_none + "\nsize          = " + c_value + "0x", \
                self.val['size'],                               \
                c_none + "\nmprotect_size = " + c_value + "0x", \
                self.val['mprotect_size'],                      \
                c_none)

    def display_string(self):
        return "string"

################################################################################
def pretty_print_heap_lookup(val):
    "Look-up and return a pretty-printer that can print val."

    # Get the type.
    type = val.type

    # If it points to a reference, get the reference.
    if type.code == gdb.TYPE_CODE_REF:
        type = type.target()

    # Get the unqualified type, stripped of typedefs.
    type = type.unqualified().strip_typedefs()

    # Get the type name.
    typename = type.tag
    if typename == None:
        return None
    elif typename == "malloc_par":
        return malloc_par_printer(val)
    elif typename == "malloc_state":
        return malloc_state_printer(val)
    elif typename == "malloc_chunk":
        return malloc_chunk_printer(val)
    elif typename == "_heap_info":
        return heap_info_printer(val)
    else:
        print typename

    # Cannot find a pretty printer.  Return None.
    return None


################################################################################
def print_fastbins(inferior, fb_base, fb_num):
    "walk and print the fast bins"


    print_title("Fastbins")

    for fb in xrange(0,NFASTBINS):
        if fb_num != None:
            fb = fb_num

        offset = fb_base + fb*SIZE_SZ
        try:
            mem = inferior.read_memory(offset, SIZE_SZ)
            if SIZE_SZ == 4:
                fd = struct.unpack("<I", mem)[0]
            elif SIZE_SZ == 8:
                fd = struct.unpack("<Q", mem)[0]
        except RuntimeError:
            print c_error + " ERROR: Invalid fb addr 0x%lx" % offset + c_none
            return

        print "%s%s%d%s%s0x%08lx%s%s%s0x%08lx%s%s" % \
                (c_header,"[ fb  ",fb," ] ",c_none,offset,\
                 " -> ",c_value,"[ ",fd," ]",c_none),

        if fd == 0: #fastbin is empty
            print ""
        else:
            print "(%d)" % ((MIN_CHUNK_SIZE) +(MALLOC_ALIGNMENT)*fb)
            chunk = malloc_chunk(fd, inuse=False)
            while (chunk.fd != 0):
                print "%s%26s0x%08lx%s%s%s" % \
                        (c_value,"[ ",chunk.fd," ] ",c_none,"(%d)" % \
                        ((MIN_CHUNK_SIZE) + (MALLOC_ALIGNMENT)*fb))
                chunk = malloc_chunk(chunk.fd, inuse=False)

        if fb_num != None: #only print one fastbin
            return


################################################################################
def print_smallbins(inferior, sb_base, sb_num):
    "walk and print the small bins"


    print("Smallbins")

    for sb in xrange(2,NBINS+2,2):
        if sb_num != None and sb_num!=0:
            sb = sb_num*2

        offset = sb_base + (sb-2)*SIZE_SZ
        try:
            mem = inferior.read_memory(offset, 2*SIZE_SZ)
            if SIZE_SZ == 4:
                fd,bk = struct.unpack("<II", mem)
            elif SIZE_SZ == 8:
                fd,bk = struct.unpack("<QQ", mem)
        except RuntimeError:
            print c_error + " ERROR: Invalid sb addr 0x%lx" % offset + c_none
            return

        print "%s%s%02d%s%s0x%08lx%s%s%s0x%08lx%s0x%08lx%s%s" % \
                            (c_header,"[ sb ",sb/2," ] ",c_none,offset, \
                            " -> ",c_value,"[ ", fd, " | ", bk, " ] ",  \
                            c_none)

        while (1):
            if fd == (offset-2*SIZE_SZ):
                break

            chunk = malloc_chunk(fd, inuse=False)
            print "%s%26s0x%08lx%s0x%08lx%s%s" % \
                    (c_value,"[ ",chunk.fd," | ",chunk.bk," ] ",c_none),
            print "(%d)" % chunk.chunksize()

            fd = chunk.fd

        if sb_num != None: #only print one smallbin
            return


################################################################################
def print_bins(inferior, fb_base, sb_base):
    "walk and print the nonempty free bins, modified from jp"

    print_title("Heap Dump")

    for fb in xrange(0,NFASTBINS):
        print_once = True
        p = malloc_chunk(fb_base-(2*SIZE_SZ)+fb*SIZE_SZ, inuse=False)

        while (p.fd != 0):
            if print_once:
                print_once = False
                print c_header + "  fast bin %d   @ 0x%lx" % \
                        (fb,p.fd) + c_none
            print "    free chunk @ " + c_value + "0x%lx" % p.fd + c_none + \
                  " - size" + c_value,
            p = malloc_chunk(p.fd, inuse=False)
            print "0x%lx" % p.chunksize() + c_none

    for i in xrange(1, NBINS):
        print_once = True
        b = sb_base + i*2*SIZE_SZ - 4*SIZE_SZ
        p = malloc_chunk(first(malloc_chunk(b, inuse=False)), inuse=False)

        while p.address != b:
            if print_once:
                print_once = False
                if i==1:
                    try:
                        print c_header + "  unsorted bin @ 0x%lx" % \
                          (b.cast(gdb.lookup_type("unsigned long")) \
                          + 2*SIZE_SZ) + c_none
                    except:
                        print c_header + "  unsorted bin @ 0x%lx" % \
                          (b + 2*SIZE_SZ) + c_none
                else:
                    try:
                        print c_header + "  small bin %d @ 0x%lx" %  \
                         (i,b.cast(gdb.lookup_type("unsigned long")) \
                         + 2*SIZE_SZ) + c_none
                    except:
                        print c_header + "  small bin %d @ 0x%lx" % \
                         (i,b + 2*SIZE_SZ) + c_none

            print c_none + "    free_chunk @ " + c_value \
                  + "0x%lx " % p.address + c_none        \
                  + "- size " + c_value + "0x%lx" % p.chunksize() + c_none

            p = malloc_chunk(first(p), inuse=False)


################################################################################
def print_containing(ar_ptr,sbr_base,addr):
    "print heap chunk containgig address"

    for h in enum_heaps(ar_ptr):
        m = chunk2mem(h)
        s = h.chunksize()
        if m <= addr and addr < h.address +s:
            print "Address 0x%x belong to: "%addr
            print "%s%14s%17s%15s%s" % (c_header, "ADDR", "SIZE", "STATUS", c_none)
            print "%schunk     %s0x%-14lx 0x%-10lx%s" % \
                (c_none, c_value, h.address, s, c_none),
            if ar_ptr.top == h.address:
                print "(top)"
            elif inuse(h):
                print "(inuse)"
            else:
                print "(free)"



def print_heap_dump(ar_ptr):
    print_title("Heap Dump")

    print c_title + "Arena(s) found:" + c_none
    try: #arena address obtained via read_var
        print "\t arena @ 0x%x" %  ar_ptr.address
    except: #arena address obtained via -a
        print "\t arena @ 0x%x" % ar_ptr.address

        if ar_ptr.address != ar_ptr.next:
                #we have more than one arena

            curr_arena = malloc_state(ar_ptr.next)
            while (ar_ptr.address != curr_arena.address):
                print "\t arena @ 0x%x" % curr_arena.address
                curr_arena = malloc_state(curr_arena.next)

                if curr_arena.address == 0:
                    print c_error + \
                        "ERROR: No arenas could be correctly found." + c_none
                    break #breaking infinite loop

        print ""

def print_flat_listing(ar_ptr, sbrk_base):
    "print a flat listing of an arena, modified from jp and arena.c"

    print_title("Heap Dump")
    print "%s%14s%17s%15s%s" % (c_header, "ADDR", "SIZE", "STATUS", c_none)
    print "sbrk_base " + c_value + "0x%lx" % sbrk_base

    # p = malloc_chunk(sbrk_base, inuse=True, read_data=False)

    # while(1):
    for p in enum_heaps(ar_ptr):
        print "%schunk     %s0x%-14lx 0x%-10lx%s" % \
                (c_none, c_value, p.address, p.chunksize(), c_none),

        if p.address == ar_ptr.top:
            print "(top)"

        elif p.size == (0|PREV_INUSE):
            print "(fence)"


        elif inuse(p):
            print "(inuse)"
        else:
            p = malloc_chunk(p.address, inuse=False)
            print "(F) FD %s0x%lx%s BK %s0x%lx%s" % \
                    (c_value, p.fd, c_none,c_value,p.bk,c_none),

            if ((p.fd == ar_ptr.last_remainder) \
            and (p.bk == ar_ptr.last_remainder) \
            and (ar_ptr.last_remainder != 0)):
                print "(LR)"
            elif ((p.fd == p.bk) & ~inuse(p)):
                print "(LC)"
            else:
                print ""

        #p = malloc_chunk(next_chunk(p), inuse=True, read_data=False)

    print c_none + "sbrk_end  " + c_value \
            + "0x%lx" % (sbrk_base + ar_ptr.system_mem) + c_none


################################################################################
def print_compact_listing(ar_ptr, sbrk_base):
    "print a compact layout of the heap, modified from jp"
    print_title("Heap Dump")
    #p = malloc_chunk(sbrk_base, inuse=True, read_data=False)

    #while(1):
    for p in enum_heaps(ar_ptr):
        if p.address == ar_ptr.top:
            sys.stdout.write("|T|\n")


        elif inuse(p):
            sys.stdout.write("|A|")
        else:
            p = malloc_chunk(p.address, inuse=False)

            if ((p.fd == ar_ptr.last_remainder) \
            and (p.bk == ar_ptr.last_remainder) \
            and (ar_ptr.last_remainder != 0)):
                sys.stdout.write("|L|")
            else:
                sys.stdout.write("|%d|" % bin_index(p.size))

        #p = malloc_chunk(next_chunk(p), inuse=True, read_data=False)


################################################################################
