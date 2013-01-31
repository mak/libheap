# ################################################################################
# class check_house_of_mind(gdb.Command):
#     "print and help validate a house of mind layout"

#     def __init__(self):
#         super(check_house_of_mind, self).__init__("check_house_of_mind",
#                                         gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

#     def invoke(self, arg, from_tty):
#         """
#         Specify the house of mind method and chunk address (p=mem2chunk(mem)):
#         check_house_of_mind method=unsortedbin p=0x12345678
#         check_house_of_mind method=fastbin p=0x12345678
#         """

#         if arg.find("method") == -1:
#             print "Please specify the House of Mind method to use:"
#             print "house_of_mind method={unsortedbin, fastbin}"
#             return
#         elif arg.find("p") == -1:
#             print "Please specify the chunk address to use:"
#             print "house_of_mind p=0x12345678"
#             return
#         else:
#             arg = arg.split()
#             for item in arg:
#                 if item.find("method") != -1:
#                     if len(item) < 8:
#                         sys.stdout.write(c_error)
#                         print "Malformed method parameter"
#                         print "Please specify the House of Mind method to use:"
#                         print "house_of_mind method={unsortedbin, fastbin}"
#                         sys.stdout.write(c_none)
#                         return
#                     else:
#                         method = item[7:]
#                 if item.find("p") != -1:
#                     if len(item) < 11:
#                         sys.stdout.write(c_error)
#                         print "Malformed chunk parameter"
#                         print "Please specify the chunk address to use:"
#                         print "house_of_mind p=0x12345678"
#                         sys.stdout.write(c_none)
#                         return
#                     else:
#                         p = int(item[2:],16)

#         sys.stdout.write(c_title)
#         print "===============================",
#         print "House of Mind ==================================\n"
#         sys.stdout.write(c_none)

#         if method.find("unsorted") != -1:
#             self.unsorted_bin_method(p)
#         elif method.find("fast") != -1:
#             self.fast_bin_method(p)

#     def unsorted_bin_method(self, p):
#         p = malloc_chunk(addr=p, inuse=True, read_data=False)

#         print c_none + "Checking chunk p"
#         print c_none + " [*] p = " + c_value + "0x%x" % p.address + c_none

#         if p.address < gdb.parse_and_eval("(unsigned int)%d" % -chunksize(p)):
#             print " [*] size does not wrap"
#         else:
#             print c_error + " [_] ERROR: p > -size" + c_none
#             return

#         if chunksize(p) >= MINSIZE:
#             print " [*] size is > minimum chunk size"
#         else:
#             print c_error + " [_] ERROR: chunksize(p) < MINSIZE" + c_none
#             return

#         if chunksize(p) > get_max_fast():
#             print " [*] size is not in fastbin range"
#         else:
#             print c_error + " [_] ERROR: size is in fastbin range" + c_none
#             return

#         if not chunk_is_mmapped(p):
#             print " [*] is_mmapped bit is not set"
#         else:
#             print c_error + " [_] ERROR: IS_MMAPPED bit is set" + c_none
#             return

#         if prev_inuse(p):
#             print " [*] prev_inuse bit is set"
#         else:
#             print c_error + " [_] ERROR: PREV_INUSE bit is not set, this will",
#             print "trigger backward consolidation" + c_none

#         if chunk_non_main_arena(p):
#             print " [*] non_main_arena flag is set"
#         else:
#             print c_error + " [_] ERROR: p's non_main_arena flag is NOT set"
#             return

#         print c_none + "\nChecking struct heap_info"
#         print c_none + " [*] struct heap_info = " \
#                 + c_value + "0x%x" % heap_for_ptr(p.address)

#         inferior = get_inferior()
#         if inferior == -1:
#             return None

#         try:
#             mem = inferior.read_memory(heap_for_ptr(p.address), SIZE_SZ)
#             if SIZE_SZ == 4:
#                 ar_ptr = struct.unpack("<I", mem)[0]
#             elif SIZE_SZ == 8:
#                 ar_ptr = struct.unpack("<Q", mem)[0]
#         except RuntimeError:
#             print c_error + " [_] ERROR: Invalid heap_info address 0x%x" \
#                     % heap_for_ptr(p.address) + c_none
#             return

#         print c_none + " [*] ar_ptr = " + c_value + "0x%x" % ar_ptr
#         print c_none + "\nChecking struct malloc_state"

#         #test malloc_state address
#         try:
#             mutex = inferior.read_memory(ar_ptr, SIZE_SZ)
#         except RuntimeError:
#             print c_error + " [_] ERROR: Invalid malloc_state address 0x%x" % \
#                     ar_ptr + c_none
#             return

#         av = malloc_state(ar_ptr)

#         if av.mutex == 0:
#             print c_none + " [*] av->mutex is zero"
#         else:
#             print c_error + " [_] ERROR: av->mutex is not zero" + c_none
#             return

#         if p.address != av.top:
#             print c_none + " [*] p is not the top chunk"
#         else:
#             print c_error + " [_] ERROR: p is the top chunk" + c_none
#             return

#         if noncontiguous(av):
#             print c_none + " [*] noncontiguous_bit is set"
#         elif contiguous(av):
#             print c_error + \
#                 " [_] ERROR: noncontiguous_bit is NOT set in av->flags" + c_none
#             return

#         print " [*] bck = &av->bins[0] = " + c_value + "0x%x" % (ar_ptr+0x38)

#         if SIZE_SZ == 4:
#             print c_none + " [*] fwd = bck->fd = *(&av->bins[0] + 8) =",
#         elif SIZE_SZ == 8:
#             print c_none + " [*] fwd = bck->fd = *(&av->bins[0] + 16) =",

#         fwd = inferior.read_memory(ar_ptr + 0x38 + 2*SIZE_SZ, SIZE_SZ)
#         if SIZE_SZ == 4:
#             fwd = struct.unpack("<I", fwd)[0]
#         elif SIZE_SZ == 8:
#             fwd = struct.unpack("<Q", fwd)[0]
#         print c_value + "0x%x" % fwd

#         if fwd != (ar_ptr+0x38):
#             print c_none + " [!] fwd->bk (0x%x) != bck (0x%x)" % \
#                     (fwd, ar_ptr+0x38) + c_error
#             print "     - ERROR: This will prevent this attack on glibc 2.11+",
#             print c_none

#         print c_none + "\nChecking following chunks"
#         nextchunk = chunk_at_offset(p, chunksize(p))

#         if prev_inuse(nextchunk):
#             print c_none + " [*] prev_inuse of the next chunk is set"
#         else:
#             print c_error + " [_] PREV_INUSE bit of the next chunk is not set" \
#                     + c_none
#             return

#         if chunksize(nextchunk) > 2*SIZE_SZ:
#             print c_none + " [*] nextchunk size is > minimum size"
#         else:
#             print c_error + " [_] ERROR: nextchunk size (%d) < %d" % \
#                     (chunksize(nextchunk), 2*SIZE_SZ) + c_none
#             return

#         if chunksize(nextchunk) < av.system_mem:
#             print c_none + " [*] nextchunk size is < av->system_mem"
#         else:
#             print c_error + " [_] ERROR: nextchunk size (0x%x) >" % \
#                     chunksize(nextchunk),
#             print "av->system_mem (0x%x)" % av.system_mem + c_none
#             return

#         if nextchunk.address != av.top:
#             print c_none + " [*] nextchunk != av->top"
#         else:
#             print c_error + " [_] ERROR: nextchunk is av->top (0x%x)" % av.top \
#                     + c_none
#             return

#         if inuse_bit_at_offset(nextchunk, chunksize(nextchunk)):
#             print c_none + " [*] prev_inuse bit set on chunk after nextchunk"
#         else:
#             print c_error + " [_] ERROR: PREV_INUSE bit of chunk after",
#             print "nextchunk (0x%x) is not set" % \
#                     (nextchunk.address + chunksize(nextchunk)) + c_none
#             return

#         print c_header + "\np (0x%x) will be written to fwd->bk (0x%x)" \
#                 % (p.address, fwd+0xC) + c_none

#     def fast_bin_method(self, p):
#         p = malloc_chunk(addr=p, inuse=True, read_data=False)

#         print c_none + "Checking chunk p"
#         print c_none + " [*] p = " + c_value + "0x%x" % p.address + c_none

#         if p.address < gdb.parse_and_eval("(unsigned int)%d" % -chunksize(p)):
#             print " [*] size does not wrap"
#         else:
#             print c_error + " [_] ERROR: p > -size" + c_none
#             return

#         if chunksize(p) >= MINSIZE:
#             print " [*] size is >= minimum chunk size"
#         else:
#             print c_error + " [_] ERROR: chunksize(p) < MINSIZE" + c_none
#             return

#         if chunksize(p) < get_max_fast():
#             print " [*] size is in fastbin range"
#         else:
#             print c_error + " [_] ERROR: size is not in fastbin range" + c_none
#             return

#         if chunk_non_main_arena(p):
#             print " [*] non_main_arena flag is set"
#         else:
#             print c_error + " [_] ERROR: p's non_main_arena flag is NOT set"
#             return

#         if prev_inuse(p):
#             print " [*] prev_inuse bit is set"
#         else:
#             print c_error + " [_] ERROR: PREV_INUSE bit is not set, this will",
#             print "trigger backward consolidation" + c_none

#         print c_none + "\nChecking struct heap_info"
#         print c_none + " [*] struct heap_info = " \
#                 + c_value + "0x%x" % heap_for_ptr(p.address)

#         inferior = get_inferior()
#         if inferior == -1:
#             return None

#         try:
#             mem = inferior.read_memory(heap_for_ptr(p.address), SIZE_SZ)
#             if SIZE_SZ == 4:
#                 ar_ptr = struct.unpack("<I", mem)[0]
#             elif SIZE_SZ == 8:
#                 ar_ptr = struct.unpack("<Q", mem)[0]
#         except RuntimeError:
#             print c_error + " [_] ERROR: Invalid heap_info address 0x%x" \
#                     % heap_for_ptr(p.address) + c_none
#             return

#         print c_none + " [*] ar_ptr = " + c_value + "0x%x" % ar_ptr
#         print c_none + "\nChecking struct malloc_state"

#         #test malloc_state address
#         try:
#             mutex = inferior.read_memory(ar_ptr, SIZE_SZ)
#         except RuntimeError:
#             print c_error + " [_] ERROR: Invalid malloc_state address 0x%x" % \
#                     ar_ptr + c_none
#             return

#         av = malloc_state(ar_ptr)

#         if av.mutex == 0:
#             print c_none + " [*] av->mutex is zero"
#         else:
#             print c_error + " [_] ERROR: av->mutex is not zero" + c_none
#             return

#         print c_none + " [*] av->system_mem is 0x%x" % av.system_mem

#         print c_none + "\nChecking following chunk"
#         nextchunk = chunk_at_offset(p, chunksize(p))
#         print " [*] nextchunk = " + c_value + "0x%x" % nextchunk.address

#         if nextchunk.size > 2*SIZE_SZ:
#             print c_none + " [*] nextchunk size is > 2*SIZE_SZ"
#         else:
#             print c_error + " [_] ERROR: nextchunk size is <= 2*SIZE_SZ" +c_none
#             return

#         if chunksize(nextchunk) < av.system_mem:
#             print c_none + " [*] nextchunk size is < av->system_mem"
#         else:
#             print c_error + " [_] ERROR: nextchunk size (0x%x) is >= " % \
#                     chunksize(nextchunk),
#             print "av->system_mem (0x%x)" % (av.system_mem) + c_none
#             return

#         fb = ar_ptr + (2*SIZE_SZ) + (fastbin_index(p.size)*SIZE_SZ)
#         print c_header + "\np (0x%x) will be written to fb (0x%x)" \
#                 % (p.address, fb) + c_none
