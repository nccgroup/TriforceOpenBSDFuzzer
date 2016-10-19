
# Privmem Disk
We added a "privmem" driver to QEMU to support booting from a
normal disk image while maintaining isolation between test cases.
To attach such a drive use the command line option
`-drive file=privmem:disk.bin`.  This will read
the contents of `disk.bin` into memory and use it as a disk
image.  Changes made to the drive will be made in memory but
will not be persisted to disk.  Any changes made in a test
case after it has forked will be private to that test case.

# Building a test image
To build a test image, begin by performing a normal install
of your operating system.  We started with a 300MB disk
in vmware and installed a minimal OpenBSD 5.9 system on it
(with bsd, bsd.rd and base59.tgz).  We then powered off that
virtual machine and attached the disk image to a second
OpenBSD VM so we could extract and edit the image.  To
extract the image we ran `dd if=/dev/wd1c of=disk.bin`.
We then performed a number of edits of the system to make
it suitable for running system call tests:
```
$ su
# vnconfig vnd0 disk.bin
# mount /dev/vnd0a /mnt
# cp $FUZZER/target/driver /mnt/bin
# cp $FUZZER/target/input/ex1 /mnt/etc
# cat > /mnt/etc/boot.conf <<_EOF_
stty com0 115200
set tty com0
_EOF_
# cat >/mnt/etc/rc <<_EOF_
#
# minimal initialization and then invoke fuzzer driver
# never return / never invoke getty/login.
#

echo "running rc!"
export TERM=vt220
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
mount -u -o rw /

echo warm JIT cache
/bin/driver -tv </etc/ex1

echo start testing
/bin/driver -v
#/bin/sh -i

echo "exiting"
/sbin/shutdown -p now
_EOF_
# umount /mnt
# vnconfig -u vnd0
```

This configures the system to boot with a serial console, and
to run the driver during the boot process (after making sure
the root partition is writable).  After preparing the disk
image, we downloaded it to our fuzzing host and executed it with:

```
AFL=../../TriforceAFL
IMG=disk.bin
KERN=bsd.gdb
TESTFILES=inputs/ex?

getSym() {
    name=$1
    gdb -batch -ex "p/x &$name" $KERN |sed 's/^.*0x//g'
}

PANIC=`getSym Debugger`
LOGSTORE=0   #XXX for now

./testAfl $AFL/afl-qemu-system-trace \
    -L $AFL/qemu_mode/qemu/pc-bios \
    -m 64M -nographic -drive format=raw,file=privmem:${IMG} \
    -aflPanicAddr "$PANIC" \
    -aflDmesgAddr "$LOGSTORE" \
    -aflFile @@ \
    -- $TESTFILES
```

This attaches the disk.bin as our primary drive and boots
from it.  It then uses testAfl to run through the inputs
from `inputs/ex?`.

