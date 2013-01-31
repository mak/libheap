try:
    import gdb
except ImportError:
    print "Not running inside of GDB, exiting..."
    exit()


import sys
import struct
from os import uname


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

def to_int(val):
    sval = str(val)

    if sval.startswith('0x'):
        return int(sval, 16)
    else:
        return int(sval)

def uint():
    return gdb.lookup_type('unsigned int')


def from_ptr(val):
    return to_int(val.cast(uint()))

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
