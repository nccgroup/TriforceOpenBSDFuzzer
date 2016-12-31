# TriforceOpenBSDSyscallFuzzer
* 20160825
* https://github.com/nccgroup/TriforceOpenBSDFuzzer
* Jesse Hertz <jesse.hertz@nccgroup.trust>
* Tim Newsham <tim.newsham@nccgroup.trust>

This is a collection of files used to perform system call
fuzzing of OpenBSD amd64 using TriforceAFL (i.e. AFL and QEMU).  To use
it you will need TriforceAFL (https://github.com/nccgroup/TriforceAFL),
the FlashRD 2.0 distribution (http://www.nmedia.net/flashrd/),
an OpenBSD box to build the driver and a disk image, and a Linux
box as host to run the fuzzer (other fuzzer hosts may work as well,
we've only run TriforceAFL from a Linux host, specifically Debian/Ubuntu).

We'll be doing everything as root on the OpenBSD box, as this box is being used just to boostrap our environment. 
If you have an existing OpenBSD box, feel free to do less of this as root. If you're an experienced OpenBSD user,
a lot of this will be overly verbose. Anyway, onwards!

On the OpenBSD box:

```
export PKG_PATH=http://mirrors.sonic.net/pub/OpenBSD/$(uname -r)/packages/$(uname -m)/
pkg_add git
pkg_add python # pick python 2.7
```


Next you'll need to pull down the OpenBSD sources, and the kernel
sources, and then unpack them:

```
cd ~
ftp http://mirrors.sonic.net/pub/OpenBSD/5.9/src.tar.gz 
ftp http://mirrors.sonic.net/pub/OpenBSD/5.9/sys.tar.gz
cd /usr/src; tar -xzpf $HOME/src.tar.gz; tar -xzpf $HOME/sys.tar.gz;
```

If you already have an install CD, no need to pull down the following files (as they'll be in $CDMOUNT/5.9/amd64/*.tgz). You'll only need to set $DISTDIR appropriately. Otherwise...

```
cd ~
ftp http://mirrors.sonic.net/pub/OpenBSD/5.9/amd64/base59.tgz
ftp http://mirrors.sonic.net/pub/OpenBSD/5.9/amd64/man59.tgz
ftp http://mirrors.sonic.net/pub/OpenBSD/5.9/amd64/comp59.tgz
ftp http://mirrors.sonic.net/pub/OpenBSD/5.9/amd64/game59.tgz
export DISTDIR=~
```

We now have the necessary dependencies installed, and can start building stuff.

Clone the TriforceOpenBSDFuzzer repository
```
git clone https://github.com/nccgroup/TriforceOpenBSDFuzzer
```
and change into its directory. There are separate directories containing the OpenBSD files (`targ`) and 
the fuzzer host files (`fuzzHost`).

## Building Driver and Inputs
On an OpenBSD host, enter the `targ` directory and run `make`.
You should also build input files from this directory
```
    mkdir inputs
    ./gen.py                   # build simple tests
    ./genTempl.py templ.txt    # build most syscall tests
    ./gen2.py                  # build complex syscall tests
    tar -czf ../inputs.tgz inputs
```

## Building Disk Image
Next you will need to build a disk image with the driver, using
the FlashRD distribution (http://www.nmedia.net/flashrd/).
On an OpenBSD host (with sources in /usr/src and kernel sources in 
/usr/src/sys from the above section), we'll now do several things:

- extract flashrd-2.0
- patch flashrd 
- create an obsd directory, and fill it with stuff!


```
    cd ~ #make sure this is on your /home parition, you will need significant disk space for this
    ftp http://www.nmedia.net/flashrd/flashrd-2.0.tar.gz
    tar xzf flashrd-2.0.tar.gz
    cd flashrd-2.0
    patch -p1 < $FUZZER/image-diff.txt #set $FUZZER to where you cloned TriforceOpenBSDFuzzer
    mkdir obsd
    cd obsd

    tar xzpf $DISTDIR/base59.tgz
    tar xzpf $DISTDIR/man59.tgz
    tar xzpf $DISTDIR/comp59.tgz
    tar xzpf $DISTDIR/game59.tgz
    tar xzpf /var/sysmerge/etc.tgz
    cp $FUZZER/image-etc-rc etc/rc
    cp $FUZZER/targ/inputs/ex1 root/ex1
    cd ..
```

You can now create an image by running these commands :
```
    cp $FUZZER/targ/driver obsd/bin/driver
    ./flashrd obsd
    mv flashimg* $FUZZER/flashimg.bin
    mv bsd.gdb $FUZZER/bsd.gdb
```
Save a copy of flashimg.bin and bsd.gdb.  You will need them
on the fuzzer host.

You may wish to create a second image for debugging that allows
you to run an interactive shell.  Edit `obsd/etc/rc` and
replace `/bin/driver -v` with `/bin/sh -i` and create a second image.
Then we'll save a copy of flashimg-sh.bin and bsd-sh.gdb for later.

```
    ./flashrd obsd
    mv flashimg* $FUZZER/flashimg-sh.bin
    mv bsd.gdb $FUZZER/bsd-sh.gdb
```

We can now leave the OpenBSD box, and return to our fuzz host (make sure to copy
$FUZZER out, so we can use it on the fuzz host). 

## Fuzzing
We run the fuzzer on a Linux host (it should work on any host
where TriforceAFL builds and runs, but YMMV, especially on a non-linux host).
On the fuzzer host, install TriforceAFL to ../TriforceAFL.
Copy the `flashimg*.bin` and `bsd*.gdb` to the `fuzzhost` directory, 
and unpack the inputs into the fuzzHost directory:

```
    cd TriforceOpenBSDFuzzer # this should now have the files we made on the BSD host in it
    cp flashimg* fuzzHost/
    cp bsd* fuzzHost/
    cd fuzzHost
    tar xzf ../inputs.tgz
```

Now we're ready to fuzz! Enter the `fuzzHost` directory 
and start the fuzzer with `./runFuzz -M M0`.

Note that the `runFuzz` script expects a master or slave name, as
it always runs in master/slave mode.  See the `runFuzz` script for
more usage information.

## Reproducing
To reproduce test cases (such as crashes), on the fuzzer host run:
```
  ./runTest inputs/ex1
  ./runTest outputs/crashes/id*
```

You can also run the driver out of the emulated environment
with the `-t` option, with verbose logging with `-vv`
and without actually performing the system calls with `-x`.
For example, on the OpenBSD host run:
```
  ./driver -tvvx < inputs/ex1
  ktrace ./driver -t < inputs/ex1
```

It is sometimes useful to be able to boot the kernel and interactively
run tests. You can run `./runSh` to boot
into an interactive shell.

You will likely want to add additional files (such as test cases)
to the `flashimg-sh.bin` file for testing.  To do this, on the
OpenBSD host copy the additional files to `flashrd-2.0/obsd/root`
and rebuild the flash image.  Transfer the files back to your
fuzzer host and execute `runSh` again.  You will find the additional
files in the `/root` directory.  You can also add files to the flash
image after creating it, as root on the OpenBSD host:
```
    vnconfig vnd0 ./flashimg.bin
    mount /dev/vnd0a /mnt
    cp file /mnt
    umount /mnt
    vnconfig -u vnd0
```
Files added here will appear in `/flash` when the image is booted

## Debugging
The patches applied earlier to the flashrd distribution will
enable debugging and disable optimization when building the kernel.
This makes debugging much easier. 

To debug the kernel from the fuzzHost, make a copy of /usr/src/sys
from your OpenBSD host, and copy `bsd-sh.gdb` to `sys/x/x/x/x`.
In one window run `./runSh` and after the system has booted run
```
    cd sys
    mkdir -p x/x/x/x
    cd x/x/x/x
    cp $FUZZER/bsd-sh.gdb .
    gdb -ex "target remote :1234" ./bsd-sh.gdb
```

