import gdb

## internal structs
from mstate import *
from mpar import *
from mchunk import *

## rest
from util import *


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



def next_bin(b):
    return (b + 1)

def first(b):
    return b.fd

def last(b):
    return b.bk


def chunk_at_offset(p, s):
    "Treat space at ptr + offset as a chunk"
    return malloc_chunk(p.address + s, inuse=False)

def inuse(p):
    "extract p's inuse bit"
    return (malloc_chunk(p.address + \
                             (p.size & ~SIZE_BITS), inuse=False).size & PREV_INUSE)

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



def get_max_fast():
    return gdb.parse_and_eval("global_max_fast")

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


def get_main_arena():
    try:

        main_arena = gdb.parse_and_eval('main_arena')
        arena_address = main_arena.address

    except RuntimeError:
        print_error("No gdb frame is currently selected.")
        return None

    except ValueError:
        print_error("Debug glibc was not found, " \
                     "guessing main_arena address via offset from libc.")

        #find heap by offset from end of libc in /proc
        libc_end,heap_begin = read_proc_maps(inferior.pid)

        if SIZE_SZ == 4:
            #__malloc_initialize_hook + 0x20
            #offset seems to be +0x380 on debug glibc, +0x3a0 otherwise
            arena_address = libc_end + 0x3a0
        elif SIZE_SZ == 8:
            #offset seems to be +0xe80 on debug glibc, +0xea0 otherwise
            arena_address = libc_end + 0xea0

            if libc_end == -1:
                print c_error + "Invalid address read via /proc" + c_none
                return None

    if arena_address == 0:
        print_error("Invalid arena address (0)")
        return None


    ar_ptr = malloc_state(arena_address)
    return ar_ptr

def get_sbrk_base(ar_ptr):
    try:
        mp_ = gdb.parse_and_eval('mp_')
        mp_address = mp_.address
    except RuntimeError:
        print_error("No gdb frame is currently selected.")
        return None
    except ValueError:
        print_info("Debug glibc was not found, " \
                   "guessing mp_ address via offset from main_arena.")

        if SIZE_SZ == 4:
            mp_address = ar_ptr.address + 0x460
        elif SIZE_SZ == 8: #offset 0x880 untested on 64bit
            mp_address = ar_ptr.address + 0x880
    sbrk_base = malloc_par(mp_address).sbrk_base
    return sbrk_base


def enum_heaps(ar_ptr):

    sbrk_base = get_sbrk_base(ar_ptr)
    p = malloc_chunk(sbrk_base, ar_ptr, inuse=True, read_data=False)
    while(1):
        yield p

        if(p.address == ar_ptr.top  or p.size == (0|PREV_INUSE)):
            break

        p = malloc_chunk(p.next_chunk(),ar_ptr, inuse=True, read_data=False)
