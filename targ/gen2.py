#!/usr/bin/env python2.7
"""
Generate some of the trickier input cases
"""
from gen import *

def sockInAddr(host, port, sz=16, family=2) :
    h = struct.pack('!I', host)
    p = struct.pack('!H', port)
    return struct.pack('@BB2s4sxxxxxxxx', sz, family, p, h)

def intptr(n) :
    return String(struct.pack('@I', n))

TEST = 0

def nextFile(nm, indexes={}) :
    if nm not in indexes :
        indexes[nm] = iter(xrange(1000))
    return 'inputs/%s_%03d' % (nm, next(indexes[nm]))
    
def mk(nm, *calls, **kw) :
    notest = kw.get('notest', False)
    fn = nextFile(nm)
    writeFn(fn, mkSyscalls(*calls))
    if TEST :
        if notest :
            print '%s skip' % fn
        elif test(fn) :
            print "%s pass" % fn
        else :
            print "%s no pass" % fn

bind = 104
tcpfd = StdFile(1)
tcpaddr = sockInAddr(0x7f000001, 1234)
sz = Len()
mk('104_bind', (bind, tcpfd, tcpaddr, sz))

setsockopt = 105
SOL_SOCKET = 0xffff
SO_REUSEADDR = 4
mk('105_setsockopt', 
    (setsockopt, tcpfd, SOL_SOCKET, SO_REUSEADDR, intptr(1), sz))

getsockopt = 118
mk('118_getsockopt',
    (getsockopt, tcpfd, SOL_SOCKET, SO_REUSEADDR, Alloc(4), intptr(4)))

# verified manually, only passes when we have a listener on localhost:1234
connect = 98
mk('098_connect',
    (connect, tcpfd, tcpaddr, sz), 
    notest=True)


# verified manually, only passes when we find the ephemeral addr
# and connect to it
# assumes tcpfd will be 3 when tests run
accept = 30
listen = 106
mk('030_accept',
    (listen, tcpfd, 5),
    (accept, 3, Alloc(16), intptr(16)),
    notest=True)

# verified manually, only passes when we find the ephemeral addr
# and connect to it
# assumes tcpfd will be 3 when tests run
mk('093_accept4',
    (listen, tcpfd, 5),
    (accept, 3, Alloc(16), intptr(16)),
    notest=True)

getpeername = 31
sockpairfd = StdFile(32)
mk('031_getpeername',
    (getpeername, sockpairfd, Alloc(16), intptr(16)))

getsockname = 32
mk('032_getsockname',
    (getsockname, sockpairfd, Alloc(16), intptr(16)))

sendto = 133
udpfd = StdFile(2)
targaddr = sockInAddr(0x08080808, 53)
mk('133_sendto',
    (sendto, udpfd, "testing", sz, 0, targaddr, sz))

# verified manually - passes when sending udp packet to 127.0.0.1:1234
# assumes udpfd will be 3
recvfrom = 29
mk('133_recvfrom',
    (bind, udpfd, sockInAddr(0x7f000001, 1234), sz),
    (recvfrom, 3, Alloc(64), sz, 0, Alloc(16), intptr(16)),
    notest=True)

sigprocmask = 48
mk('048_sigprocmask',
    (sigprocmask, 1, intptr(1), intptr(0)))

# always "errors" by definition. also blocks
sigsuspend = 111
mk('111_sigsuspend',
    (sigsuspend, intptr(1)),
    notest=True)

# requires root. manually verified
mount = 21
# this is a structure but we use an iovec so we can reference other args
# this works because the fields we care about are aligned
tmpfsargs = Vec64(
    StringZ("/bogus/name"),        # args.fspec
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, # args.export_info
    0,                             # args.base
    1024*4096,                     # args.size
    )
mk('021_mount',
    (mount, StringZ("tmpfs"), StringZ("/tmp"), 0, tmpfsargs),
    notest=True)

# requires root. verified manually
# although the ref works, its probably a horrible fuzz input
# test case because there is no fuzzing of the file handle passed
# in to 264_fhopen! so we include one with a buffer for the fuzzer
# to try to work with.
getfh = 161
fhopen = 264
# XXX a better starting filehandle would be one that we knew
# would work in our flashrd system on one of the tmpfs's.
# XXX investigate if there is a stable one we can use.
fh = String('\x00' * 20)
mk('264_fhopen',
    (getfh, StringZ("/.profile"), Alloc(20)),
    (fhopen, Ref(0,1), 0),
    notest=True)
mk('264_fhopen',
    (fhopen, fh, 0),
    notest=True)

# requires root. verified manually
fhstat = 294
mk('294_fhstat',
    (getfh, StringZ("/.profile"), Alloc(20)),
    (fhstat, Ref(0,1), Alloc(1024)),
    notest=True)
mk('294_fhstat',
    (fhstat, fh, Alloc(1024)),
    notest=True)

# requires root. verified manually
fhstatfs = 65
mk('065_fhstatfs',
    (getfh, StringZ("/.profile"), Alloc(20)),
    (fhstatfs, Ref(0,1), Alloc(1024)),
    notest=True)
mk('065_fhstatfs',
    (fhstatfs, fh, Alloc(1024)),
    notest=True)

select = 71
bit0    = "\x01\x00\x00\x00"
bitNone = "\x00\x00\x00\x00"
time_1sec = Vec64(1, 0)
mk('072_select',
    (select, 3, bit0, bitNone, bitNone, time_1sec))

pselect = 110
mk('110_pselect',
    (pselect, 3, bit0, bitNone, bitNone, time_1sec, intptr(1)))

def mkPollFd(fd, ev, rev) :
    return struct.pack('@iHH', fd, ev, rev)

# verified
# sometimes blocks in testing, why??
ppoll = 109
pollfds = Vec64(mkPollFd(0,1,0), mkPollFd(-1, 1, 0))
mk('109_ppoll',
    (ppoll, pollfds, sz, time_1sec, intptr(1)),
    notest=True)

kevent = 72
kq = StdFile(38)
ev_add = 1
ev_disable = 8
evfilter_read = 0xffff
stdin = 0
changes = Vec64(
    # changes[0]
    stdin,
    evfilter_read | (ev_add << 16) | (0 << 32),
    0,
    Alloc(5),

    # changes[1]
    File("stuff here"),
    evfilter_read | ((ev_add | ev_disable) << 16) | (0 << 32),
    0,
    0x12345
    )
events = Alloc(5 * 32)
mk('072_kevent',
    (kevent, kq, changes, 2, events, 5, time_1sec))
mk('072_kevent',
    (kevent, kq, 0, 0, events, 5, time_1sec))

sigaltstack = 288
altstack = Vec64(Alloc(4*4096), 4*4096, 0)
mk('288_sigaltstack',
    (sigaltstack, altstack, Alloc(24)))

fcntl = 92
f_dupfd = 0
f_setown = 6
f_setlk = 8
filefd = File("stuff here")
flock = Vec32(
    0,0,   # u64 start
    0,0,   # u64 len
    ChildPid, # u32 pid
    1)     # u16 type = F_RDLK / u16 whence = SEEK_SET

for fd in (0, filefd, sockpairfd) :
    mk('092_fcntl',
        (fcntl, fd, f_dupfd, 0))
for fd in (0, filefd, sockpairfd) :
    # works for socket. verified manually
    mk('092_fcntl',
        (fcntl, fd, f_setown, Vec64(ChildPid)),
        notest=True)
for fd in (0, filefd, sockpairfd) :
    # works for stdin and file.  verified manually
    mk('092_fcntl',
        (fcntl, fd, f_setlk, flock),
        notest=True)

# note: mmap needs extra padding arg!
mprotect = 74
mmap = 197
addr = 0x100000
map_fixed = 0x10
map_anon = 0x1000
neg1 = 0xffffffffffffffff
mk('074_mprotect',
    (mmap, addr, 4*4096, 7, map_fixed|map_anon, neg1, 0, 0),
    (mprotect, addr, 2*4096, 1))

madvise = 75
mk('075_madvise',
    (mmap, addr, 4*4096, 7, map_fixed|map_anon, neg1, 0, 0),
    (madvise, addr, 2*4096, 0))

mlock = 203
mk('203_mlock',
    (mmap, addr, 4*4096, 7, map_fixed|map_anon, neg1, 0, 0),
    (mlock, addr, 2*4096))

munlock = 204
mk('203_munlock',
    (mmap, addr, 4*4096, 7, map_fixed|map_anon, neg1, 0, 0),
    (munlock, addr, 2*4096))

minherit = 250
MAP_INHERIT_NONE = 2
mk('250_minherit',
    (mmap, addr, 4*4096, 7, map_fixed|map_anon, neg1, 0, 0),
    (minherit, addr, 2*4096, MAP_INHERIT_NONE))

msync = 256
ms_async = 1
mk('256_msync',
    (mmap, addr, 4*4096, 7, map_fixed|map_anon, neg1, 0, 0),
    (msync, addr, 2*4096, ms_async))

# XXX this is broken. dont think we can get a good test for this,
# but want it in our corpus for testing.
sigreturn = 103
mk('103_sigreturn',
    (sigreturn, 224*'\x00'))

semget = 221
ipc_private = 0
ipc_creat = 01000
mk('221_semget',
    (semget, ipc_private, 5, ipc_creat | 0666))

def mkSemBuf(num, op, flg) :
    return struct.pack('@Hhh', num, op, flg)

# assumes the first semaphore is 65536
# XXX unverfied.. having problems reclaiming semid's 
semop = 290
semops = Vec64(mkSemBuf(0,1,0), mkSemBuf(1,1,0), mkSemBuf(2,1,0))
mk('290_semop',
    (semget, ipc_private, 5, ipc_creat | 0666),
    (semop, 65536, semops, 3),
    notest=True)

# XXX unverified
# assumes the first semaphore is 65536
__semctl = 295
setval = 8
mk('295_semctl',
    (semget, ipc_private, 5, ipc_creat | 0666),
    (__semctl, 65536, 0, setval, 1))

# two of these only works for root.
sysctl = 202
kern_maxproc = Vec32(1,6)
mk('202_sysctl',
    (sysctl, kern_maxproc, sz, Alloc(4), Vec64(4), intptr(1309), 4),
    notest=True)
mk('202_sysctl',
    (sysctl, kern_maxproc, sz, 0, Vec64(4), intptr(1308), 4),
    notest=True)
mk('202_sysctl',
    (sysctl, kern_maxproc, sz, Alloc(4), Vec64(4), 0, 4))

