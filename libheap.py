try:
    import gdb
except ImportError:
    print "Not running inside of GDB, exiting..."
    exit()

import sys,os
import struct


HEAPFILE = os.path.abspath(os.path.expanduser(__file__))
if os.path.islink(HEAPFILE):
    HEAPFILE = os.readlink(HEAPFILE)
sys.path.append(os.path.dirname(HEAPFILE))



from util import *
from ptmalloc import *
from ppr import *
from house import *



################################################################################
# GDB COMMANDS
################################################################################

class print_malloc_stats(gdb.Command):
    "print general malloc stats, adapted from malloc.c mSTATs()"

    def __init__(self):
        super(print_malloc_stats, self).__init__("print_mstats",
                                        gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        "Specify an optional arena addr: print_mstats main_arena=0x12345"

        try:

            mp = malloc_par(gdb.parse_and_eval('mp_').address)

            if arg.find("main_arena") == -1:

                main_arena = gdb.parse_and_eval('main_arena')
                main_arena_address = main_arena.address
            else:
                arg = arg.split()
                for item in arg:
                    if item.find("main_arena") != -1:
                        if len(item) < 12:
                            sys.stdout.write(c_error)
                            print "Malformed main_arena parameter"
                            sys.stdout.write(c_none)
                            return
                        else:
                            main_arena_address = int(item[11:],16)
        except RuntimeError:
            error("No frame is currently selected.")

        except ValueError:
            error("Debug glibc was not found.")

        if main_arena_address == 0:
            error("Invalid main_arena address (0)")

        in_use_b = mp.mmapped_mem
        system_b = in_use_b

        arena = 0

        while(1):
            ar_ptr = malloc_state(main_arena_address)
            ar_ptr.mutex_lock()
            print_title("Malloc Stats")



            # account for top

            avail = (malloc_chunk(top(ar_ptr), inuse=True, \
                    read_data=False)).chunksize()

            nblocks = 1

            nfastblocks = 0
            fastavail = 0

            # traverse fastbins
            for i in xrange(NFASTBINS):
                p = fastbin(ar_ptr, i)
                while p!=0:

                    p = malloc_chunk(p, inuse=False)
                    nfastblocks += 1
                    fastavail += p.chunksize()
                    p = p.fd

            avail += fastavail

            # traverse regular bins
            for i in xrange(1, NBINS):
                b = ar_ptr.bin_at(i)

                a = malloc_chunk(b,inuse=False)
                p = malloc_chunk(first(a),inuse=False)

                while p.address != b:
                    nblocks += 1
                    avail += p.chunksize()
                    p = malloc_chunk(first(p), inuse=False)


            print_header("Arena %d:" % arena)


            print_value("system bytes     = ","0x%x" % ar_ptr.system_mem)
            print_value("in use bytes     = ","0x%x\n" % (ar_ptr.system_mem - avail))


            system_b += ar_ptr.system_mem
            in_use_b += (ar_ptr.system_mem - avail)

            ar_ptr.mutex_unlock()
            if ar_ptr.next == ar_ptr.address:
                break
            else:
                ar_ptr = malloc_state(ar_ptr.next)
                arena += 1

        print_header("Total (including mmap):")
        print_value("system bytes     = ","0x%x" % system_b)
        print_value("in use bytes     = ","0x%x" % in_use_b)
        print_value("max system bytes = ","0x%x" % mp.max_total_mem)
        print_value("max mmap regions = ","0x%x" % mp.max_n_mmaps)
        print_value("max mmap bytes   = ","0x%lx" % mp.max_mmapped_mem)


################################################################################
class heap(gdb.Command):
    "print a comprehensive view of the heap"

    def __init__(self):
        super(heap, self).__init__("heap", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def usage(self):
        print_title("Heap Dump Help")
        print c_title + "Options:\n" + c_none
        print c_header + "  -a 0x1234" + c_none \
            + "\tSpecify an arena address"
        print c_header + "  -b" + c_none + \
            "\t\tPrint compact bin listing (only free chunks)"
        print c_header + "  -c" + c_none + \
            "\t\tPrint compact arena listing (all chunks)"
        print c_header + "  -f [#]" + c_none + \
            "\tPrint all fast bins, or only a single fast bin"
        print c_header + "  -l" + c_none + \
            "\t\tPrint a flat listing of all chunks in an arena"
        print c_header + "  -s [#]" + c_none + \
                "\tPrint all small bins, or only a single small bin\n"
        print c_header + "  -p 0xdeadbee" + c_none +\
            "\tPrint chunk containing address"

    def invoke(self, arg, from_tty):
        "Usage can be obtained via heap -h"

        inferior = get_inferior()
        args = parse_argv(arg)



        if '-h' in args:
            self.usage()
            return

        if '-a' in args and isnum(args['-a']):
            ar_ptr = malloc_state(args['-a'])
        else:
            ar_ptr = get_main_arena()

        if not ar_ptr:
            print_error("Cannot find main_arena")
            return

        if not args:
            print_heap_dump(ar_ptr)
            return

        sbrk_base = get_sbrk_base(ar_ptr)
        fb_base = ar_ptr.address + 8
        if SIZE_SZ == 4:
            sb_base = ar_ptr.address + 56
        elif SIZE_SZ == 8:
            sb_base = ar_ptr.address + 104

        if not sbrk_base:
            print_error("Cannot find sbrk_base")
            return

        if '-l' in args:
            print_flat_listing(ar_ptr, sbrk_base)
            print ""
        if '-b' in args:
            print_bins(inferior, fb_base, sb_base)
            print ""
        if '-c' in args:
            print_compact_listing(ar_ptr, sbrk_base)
            print ""
        if '-s' in args:
            sb_number = args['-s'] if isnum(args['-s']) else None
            print sb_number
            print_smallbins(inferior, sb_base, sb_number)
            print ""
        if '-f' in args:
            fb_number = args['-f'] if isnum(args['-f']) else None
            print_fastbins(inferior, fb_base, fb_number)
            print ""
        if '-p' in args:
            print_containing(ar_ptr,sbrk_base,normalize(args['-p']))

############################################################################


class print_bin_layout(gdb.Command):
    "dump the layout of a free bin"

    def __init__(self):
        super(print_bin_layout, self).__init__("print_bin_layout",
                                        gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        "Specify an optional arena addr: print_bin_layout main_arena=0x12345"

        if len(arg) == 0:
            print_error("Please specify the free bin to dump")
            return

        try:
            if arg.find("main_arena") == -1:
#                main_arena = gdb.selected_frame().read_var('main_arena')
	        main_arena = gdb.parse_and_eval('main_arena')
                main_arena_address = main_arena.address
            else:
                arg = arg.split()
                for item in arg:
                    if item.find("main_arena") != -1:
                        if len(item) < 12:
                            print_error("Malformed main_arena parameter")
                            return
                        else:
                            main_arena_address = int(item[11:],16)
        except RuntimeError:
            print_error("No frame is currently selected.")
            return
        except ValueError:
            print_error("Debug glibc was not found.")
            return

        if main_arena_address == 0:
            print_error("Invalid main_arena address (0)")
            return

        ar_ptr = malloc_state(main_arena_address)
        ar_ptr.mutex_lock()

        print_title("Bin Layout")

        b = ar_ptr.bin_at(int(arg))
        p = malloc_chunk(first(malloc_chunk(b, inuse=False)), inuse=False)
        print_once = True
        print_str  = ""
        count      = 0

        while p.address != b:
            if print_once:
                print_once=False
                print_str += "-->  " + c_value + "[bin %d]" % int(arg) + c_none
                count += 1

            print_str += "  <-->  " + c_value + "0x%lx" % p.address + c_none
            count += 1
            #print_str += "  <-->  0x%lx" % p.address
            p = malloc_chunk(first(p), inuse=False)

        if len(print_str) != 0:
            print_str += "  <--"
            print print_str
            print "%s%s%s" % ("|"," " * (len(print_str) - 2 - count*12),"|")
            print "%s" % ("-" * (len(print_str) - count*12))
        else:
            print "Bin %d empty." % int(arg)



        ar_ptr.mutex_unlock()


################################################################################
# INITIALIZE CUSTOM GDB CODE
################################################################################

heap()
print_malloc_stats()
print_bin_layout()
#check_house_of_mind()
gdb.pretty_printers.append(pretty_print_heap_lookup)
