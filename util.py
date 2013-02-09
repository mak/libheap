try:
    import gdb
except ImportError:
    print "Not running inside of GDB, exiting..."
    exit()


import sys,struct,shlex,re


def isx86():
    return gdb.lookup_type('int').pointer().sizeof == 4

def regs():
    if isx86():
        regs = ['eax','ebx','ecx','edx','edi','esi','ebp','esp','eip']
    else:
        regs = ['rax','rbx','rcx','rdx','rdi','rsi','rbp','rsp','rip'] +\
               ['r%d' % i for i in range(8, 16)]

    return regs

# bash color support
color_support = True
if color_support:
    c_red      = "\033[31m"
    c_red_b    = "\033[01;31m"
    c_green    = "\033[32m"
    c_green_b  = "\033[01;32m"
    c_yellow   = "\033[33m"
    c_yellow_b = "\033[01;33m"
    c_blue     = "\033[34m"
    c_blue_b   = "\033[01;34m"
    c_purple   = "\033[35m"
    c_purple_b = "\033[01;35m"
    c_teal     = "\033[36m"
    c_teal_b   = "\033[01;36m"
    c_none     = "\033[0m"
else:
    c_red      = ""
    c_red_b    = ""
    c_green    = ""
    c_green_b  = ""
    c_yellow   = ""
    c_yellow_b = ""
    c_blue     = ""
    c_blue_b   = ""
    c_purple   = ""
    c_purple_b = ""
    c_teal     = ""
    c_teal_b   = ""
    c_none     = ""
c_error  = c_red
c_title  = c_green_b
c_header = c_yellow_b
c_value  = c_blue_b
c_info   = c_yellow

def print_error(s):
    sys.stdout.write(c_error)
    print "[!] " + s
    sys.stdout.write(c_none)

def print_title(s):
    sys.stdout.write(c_title)
    sys.stdout.write("================================== ")
    sys.stdout.write(s)
    sys.stdout.write(" ===================================\n")
    sys.stdout.write(c_none)

def print_value(n,v):
    print c_none + n + c_value + v + c_none

def print_header(h):
    sys.stdout.write(c_header)
    print h
    sys.stdout.write(c_none)

def print_info(i):
    sys.stdout.write(c_info)
    print "[!]" + s
    sys.stdout.write(c_none)


def error(s):
    print_error(s)
    exit

def parse_argv(args):

    args = shlex.split(args)
    options = {k: True if v.startswith('-') else myint(v) if myint(v) else v
               for k,v in zip(args, args[1:]+["--"]) if k.startswith('-')}
    return options


def normalize(a):

    if isnum(a):
        return a

    if type(a) == str and a in regs():
        return getreg(a)

    ## unreached
    return None


def normalize_long(l):
    return (0xffffffff if isx86() else 0xffffffffffffffff) & l

def getreg(r):

    e = ('$' if r[0] != '$' else '' ) + r
    return normalize_long(long(gdb.parse_and_eval(e)))

def myint(val):
    sval = str(val)

    if sval.startswith('0x'):
        return int(sval, 16)
    else:
        try:
            return int(sval)
        except:
            return None

def isnum(x):
    return type(x) in [int,long]


def uint():
    return gdb.lookup_type('unsigned int')

import traceback
def from_ptr(val):
    try:
        return myint(val.cast(uint()))
    except:
         traceback.print_exc(10)

def get_inferior():

    try:
        if len(gdb.inferiors()) == 0:
            error("No gdb inferior could be found.")
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        error("This gdb's python support is too old.")



def read_proc_maps(pid):
    '''
    Locate the stack of a process using /proc/pid/maps.
    Will not work on hardened machines (grsec).
    '''

    filename = '/proc/%d/maps' % pid

    try:
        fd = open(filename)
    except IOError:
        print c_error + "Unable to open %s" % filename + c_none
        return -1,-1

    found = libc_begin = libc_end = heap_begin = heap_end = 0
    for line in fd:
        if line.find("libc-") != -1:
            fields = line.split()

            libc_begin,libc_end = fields[0].split('-')
            libc_begin = int(libc_begin,16)
            libc_end = int(libc_end,16)
        elif line.find("heap") != -1:
            fields = line.split()

            heap_begin,heap_end= fields[0].split('-')
            heap_begin = int(heap_begin,16)
            heap_end = int(heap_end,16)

    fd.close()

    if libc_begin==0 or libc_end==0:
        error("Unable to read libc address information via /proc")
        return -1,-1

    if heap_begin==0 or heap_end==0:
        error("Unable to read heap address information via /proc")

    return libc_end,heap_begin


def vmmap(name=None):

 result = []
 pid = get_inferior().pid
 if not pid: # not running
     return None

 if name == "binary":
     name = self.getfile()
 if name is None or name == "all":
     name = ""

        # retrieve all maps
     maps = []


     ## olac remote
     # if self.is_target_remote(): # remote target
     #     tmp = tmpfile()
     #     self.execute("remote get /proc/%s/maps %s" % (pid, tmp.name))
     #     tmp.seek(0)
     #     out = tmp.read()
     #     tmp.close
     # else: # local target
     out = open("/proc/%s/maps" % pid).read()

     p = re.compile("([0-9a-f]*)-([0-9a-f]*) ([rwxps-]*)( .*){3} (.*)")
     matches = p.findall(out)
     if matches:
         for (start, end, perm, _, mapname) in matches:
             start = myint("0x%s" % start)
             end = myint("0x%s" % end)
             if mapname == "":
                 mapname = "mapped"
             maps += [(start, end, perm, mapname)]

         if myint(name) is None:
             for (start, end, perm, mapname) in maps:
                 if name in mapname:
                     result += [(start, end, perm, mapname)]
         else:
            addr = to_int(name)
            for (start, end, perm, mapname) in maps:
                if start <= addr and addr < end:
                    result += [(start, end, perm, mapname)]

     return result

    # @memoized
    # def get_vmrange(self, address, maps=None):
    #     """
    #     Get virtual memory mapping range of an address

    #     Args:
    #         - address: target address (Int)
    #         - maps: only find in provided maps (List)

    #     Returns:
    #         - tuple of virtual memory info (start, end, perm, mapname)
    #     """
    #     if maps is None:
    #         maps = self.get_vmmap()
    #     if maps:
    #         for (start, end, perm, mapname) in maps:
    #             if start <= address and end > address:
    #                 return (start, end, perm, mapname)
    #     return None
