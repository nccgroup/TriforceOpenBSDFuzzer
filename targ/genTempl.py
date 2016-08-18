#!/usr/bin/env python2.7
"""
Generate syscalls from template.
"""

import os, sys
from gen import *

class Error(Exception) :
    pass

def words(l) :
    if '#' in l :
        l = l[:l.index('#')]
    return filter(None, l.strip().split(' '))

def lineWords(fn) :
    for n,l in enumerate(file(fn, 'r')) :
        ws = words(l)
        if ws :
            yield n+1, ws

def genArg(a) :
    """Generate a list of arg values for this argument generator."""
    if a.startswith('0x') :	# hex numbers
        return [Num(int(a[2:], 16))]
    elif a.startswith('0') and a != '0' : # octal numbers
        return [Num(int(a[1:], 8))]
    elif a.isdigit() : 		# decimal numbers
        return [Num(int(a, 10))]
    elif a.startswith('32[') :	# vec32
        if a[-1] != ']' :
            Error("bad vec arg %r" % a)
        vec = a[3:-1].split(',')
        return [Vec32(*xs) for xs in genArgs(vec)]
    elif a[0] == '[' :		# vec64
        if a[-1] != ']' :
            Error("bad vec arg %r" % a)
        vec = a[1:-1].split(',')
        return [Vec64(*xs) for xs in genArgs(vec)]
    elif a[0] == '{' :          # union of several other arg types
        if a[-1] != '}' :
            Error("bad union arg %r" % a)
        its = a[1:-1].split(';')
        res = []
        for it in its :
            res += genArg(it)
        return res
    elif a[0] == '"' :		# string literal as buffer
        if a[-1] != '"' :
            Error("bad string arg %r" % a)
	return [StringZ(a[1:-1])]
    elif a == 'fd' :		# file descriptor options
	# stdfile0 = "/"
        return [Num(1), File("stuffhere"), StdFile(0)]
    elif a == 'fn' :		# filename options
        return [StringZ("/tmp/file9"), StringZ("/"), StringZ("/tmp"), Filename("#!/bin/sh\necho hi\n")]
    elif a == 'str' :		# initialized string/buffer options
        return [StringZ("testing"), Alloc(256), Filename("stuffhere")]
    elif a == 'buf' :		# alloc uninitialized buffer options
        return [Alloc(128), Alloc(4096)]
    elif a == 'sz' :		# sizes
        return [Len()]
    elif a == 'pid' :		# proc id options
        return [Num(0), Num(0xffffffffffffffff), MyPid, PPid, ChildPid]
    else :
        raise Error("bad arg type %r" % a)

def _cross(xs) :
    if xs == [] :
        yield []
    else :
        hds,tls = xs[0], xs[1:]
        for hd in hds :
            for tl in _cross(tls) :
                yield [hd] + tl

def cross(xs) :
    return _cross(list(xs))

def genArgs(gens) :
    return cross(genArg(g) for g in gens)

TEST=0

def genCalls(nr, nm, args, notest) :
    #print nr, nm, args
    passed = 0
    for n,xargs in enumerate(genArgs(args)) :
	fn = 'inputs/%03d_%s_%03d' % (nr, nm, n)
        #print fn, nr, n, nm, xargs
	call = tuple([nr] + xargs)
    	writeFn(fn, mkSyscalls(call))
        if TEST and not notest :
            if test(fn) :
                passed += 1
    if TEST and not notest and not passed :
        print nr, nm, "no pass"

def proc(fn) :
    for lno,ws in lineWords(fn) :
        notest = False
        if not ws[0].isdigit() :
            notest = True
            ws = ws[1:]
        call = int(ws[0])
        name = ws[1]
        args = ws[2:]
        genCalls(call, name, args, notest)

def main() :
    for fn in sys.argv[1:] :
        proc(fn)

if __name__ == '__main__' :
    main()
