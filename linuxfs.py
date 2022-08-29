"""This module implements a pure-Python wrapper around various
Linux-specific filesystem functions."""
#+
# Copyright 2022 Lawrence D'Oliveiro <ldo@geek-central.gen.nz>.
# Licensed under the GNU Lesser General Public License v2.1 or later.
#-

import os
import enum
import ctypes as ct
import atexit

#+
# Useful stuff
#-

def make_funcptr(lib, name) :
    "returns a new, unique ctypes object representing the same" \
    " entry point in lib named name. This can have its own argtypes" \
    " and restype definitions, distinct from any other object representing" \
    " the same entry point."
    ep = getattr(lib, name)
    return \
        type(ep).from_address(ct.addressof(ep))
#end make_funcptr

#+
# Low-level definitions
#-

libc = ct.CDLL("libc.so.6", use_errno = True)

# following comes from /usr/include/bits/fcntl-linux.h or /usr/include/linux/fcntl.h
AT_FDCWD = -100 # special fd value indicating current working directory
AT_EMPTY_PATH = 0x1000 # needs CAP_DAC_READ_SEARCH privilege to use
AT_SYMLINK_FOLLOW = 0x400 # no special privileges necessary

class SYS :
    "syscall codes."
    # actual numeric syscall codes (__NR_xxx) can be found in /usr/include/asm-generic/unistd.h.
    # /usr/include/bits/syscall.h just defines SYS_xxx synonyms for these.
    linkat = 37
    openat2 = 437
#end SYS

def def_syscall(name, code, args, res) :
    "creates a function which invokes syscall(2) with the given code and taking" \
    " additional arguments with the given types, returning a result of the given" \
    " type."
    func = make_funcptr(libc, "syscall")
    func.argtypes = (ct.c_long,) + args
    func.restype = res

    def callit(*args) :
        return \
            func(code, *args)
    #end callit

#begin def_syscall
    callit.__name__ = name
    return \
        callit
#end def_syscall

class OPENAT2 :
    "definitions from /usr/include/linux/openat2.h."

    class open_how(ct.Structure) :
        _fields_ = \
            [
                ("flags", ct.c_uint64),
                ("mode", ct.c_uint64),
                ("resolve", ct.c_uint64),
            ]
    #end open_how

    # mask bits for open_how.resolve
    RESOLVE_NO_XDEV = 0x01 # no crossing mount points
    RESOLVE_NO_MAGICLINKS = 0x02 # no following “magic symlinks”
    RESOLVE_NO_SYMLINKS = 0x04 # no following any symlinks, magic or otherwise
    RESOLVE_BENEATH = 0x08 # no going above hierarchy of dirfd
    RESOLVE_IN_ROOT = 0x10 # interpret “/” and “..” as staying within dirfd, as though chroot were in effect
    RESOLVE_CACHED = 0x20 # only do cached lookups, may return -EAGAIN

#end OPENAT2

libc.ioctl.argtypes = (ct.c_int, ct.c_ulong, ct.c_void_p)
libc.ioctl.restype = ct.c_int
libc.linkat.argtypes = (ct.c_int, ct.c_char_p, ct.c_int, ct.c_char_p, ct.c_int)
libc.linkat.restype = ct.c_int

openat2 = def_syscall \
  (
    "openat2",
    SYS.openat2,
    (ct.c_int, ct.c_char_p, ct.POINTER(OPENAT2.open_how), ct.c_size_t),
    ct.c_long
  )

class _IOC :
    # from </usr/include/asm-generic/ioctl.h>
    NRBITS = 8
    TYPEBITS = 8

    SIZEBITS = 14 # note -- architecture-specific!
    DIRBITS = 2 # note -- architecture-specific!

    NRMASK = (1 << NRBITS) - 1
    TYPEMASK = (1 << TYPEBITS) - 1
    SIZEMASK = (1 << SIZEBITS) - 1
    DIRMASK = (1 << DIRBITS) - 1

    NRSHIFT = 0
    TYPESHIFT = NRSHIFT + NRBITS
    SIZESHIFT = TYPESHIFT + TYPEBITS
    DIRSHIFT = SIZESHIFT + SIZEBITS

    NONE = 0 # note -- architecture-specific!
    WRITE = 1 # note -- architecture-specific!
    READ = 2 # note -- architecture-specific!
    TYPECHECK = lambda t : \
        (
            (
                lambda : ct.sizeof(t),
                lambda : t,
            )[isinstance(t, int)]()
        )

    # for decoding codes constructed by _IOC() and derivatives:
    DIR = lambda nr : nr >> DIRSHIFT & DIRMASK
    TYPE = lambda nr : nr >> TYPESHIFT & TYPEMASK
    NR = lambda nr : nr >> NRSHIFT & NRMASK
    SIZE = lambda nr : nr >> SIZESHIFT & SIZEMASK

#end _IOC
_IOC.IOC = lambda dir, type, nr, size : \
    (
        dir << _IOC.DIRSHIFT
    |
            (
                lambda : type,
                lambda : ord(type),
            )[isinstance(type, str)]()
        <<
            _IOC.TYPESHIFT
    |
        nr << _IOC.NRSHIFT
    |
        size << _IOC.SIZESHIFT
    )
# convenience wrappers around IOC():
_IOC.IO = lambda type, nr : _IOC.IOC(_IOC.NONE, type, nr, 0)
_IOC.IOR = lambda type, nr, size : _IOC.IOC(_IOC.READ, type, nr, _IOC.TYPECHECK(size))
_IOC.IOW = lambda type, nr, size : _IOC.IOC(_IOC.WRITE, type, nr, _IOC.TYPECHECK(size))
_IOC.IOWR = lambda type, nr, size : _IOC.IOC(_IOC.READ | _IOC.WRITE, type, nr, _IOC.TYPECHECK(size))
_IOC.IOR_BAD = lambda type, nr, size : _IOC.IOC(_IOC.READ, type, nr, ct.sizeof(size))
_IOC.IOW_BAD = lambda type, nr, size : _IOC.IOC(_IOC.WRITE, type, nr, ct.sizeof(size))
_IOC.IOWR_BAD = lambda type, nr, size : _IOC.IOC(_IOC.READ | _IOC.WRITE, type, nr, sizeof(size))

class FS :
    "definitions of codes and flag bits that you will need."

    # from </usr/include/linux/fs.h>
    # Note this is not the same thing as “extended attributes” (xattr(7)),
    # for which standard Python library calls already exist.
    class xattr(ct.Structure) :
        _fields_ = \
            [
                ("fsx_xflags", ct.c_uint32),
                ("fsx_extsize", ct.c_uint32),
                ("fsx_nextents", ct.c_uint32),
                ("fsx_projid", ct.c_uint32),
                ("fsx_cowextsize", ct.c_uint32),
                ("fsx_pad", 8 * ct.c_ubyte),
            ]

        def copy(self) :
            celf = type(self)
            res = celf()
            for f in celf._fields_ :
                setattr(res, f[0], getattr(self, f[0]))
            #end for
            return \
                res
        #end copy

        def __repr__(self) :
            return \
                (
                    "(%s)"
                %
                    ", ".join
                      (
                            "%%s = %s" % ("%d", "%#0.8x")[f == "fsx_xflags"]
                        %
                            (f, getattr(self, f))
                        for f in
                            ("fsx_xflags", "fsx_extsize", "fsx_nextents", "fsx_projid", "fsx_cowextsize")
                      )
                )
        #end __repr__

    #end xattr

    XFLAG_REALTIME = 0x00000001
    XFLAG_PREALLOC = 0x00000002
    XFLAG_IMMUTABLE = 0x00000008
    XFLAG_APPEND = 0x00000010
    XFLAG_SYNC = 0x00000020
    XFLAG_NOATIME = 0x00000040
    XFLAG_NODUMP = 0x00000080
    XFLAG_RTINHERIT = 0x00000100
    XFLAG_PROJINHERIT = 0x00000200
    XFLAG_NOSYMLINKS = 0x00000400
    XFLAG_EXTSIZE = 0x00000800
    XFLAG_EXTSZINHERIT = 0x00001000
    XFLAG_NODEFRAG = 0x00002000
    XFLAG_FILESTREAM = 0x00004000
    XFLAG_DAX = 0x00008000
    XFLAG_COWEXTSIZE = 0x00010000
    XFLAG_HASATTR = 0x80000000

    FSLABEL_MAX = 256

    IOC_GETFLAGS = _IOC.IOR('f', 1, ct.c_long)
    IOC_SETFLAGS = _IOC.IOW('f', 2, ct.c_long)
    IOC_GETVERSION = _IOC.IOR('v', 1, ct.c_long)
    IOC_SETVERSION = _IOC.IOW('v', 2, ct.c_long)
    # IOC_FIEMAP = _IOC.IOWR('f', 11, struct fiemap) # from </usr/include/linux/fiemap.h>
    IOC32_GETFLAGS = _IOC.IOR('f', 1, ct.c_int)
    IOC32_SETFLAGS = _IOC.IOW('f', 2, ct.c_int)
    IOC32_GETVERSION = _IOC.IOR('v', 1, ct.c_int)
    IOC32_SETVERSION = _IOC.IOW('v', 2, ct.c_int)
    IOC_FSGETXATTR = _IOC.IOR('X', 31, xattr)
    IOC_FSSETXATTR = _IOC.IOW('X', 32, xattr)
    IOC_GETFSLABEL = _IOC.IOR(0x94, 49, FSLABEL_MAX)
    IOC_SETFSLABEL = _IOC.IOW(0x94, 50, FSLABEL_MAX)

    # see ioctl_iflags(2) man page for info about these
    SECRM_FL = 0x00000001
    UNRM_FL = 0x00000002
    COMPR_FL = 0x00000004
    SYNC_FL = 0x00000008
    IMMUTABLE_FL = 0x00000010
    APPEND_FL = 0x00000020
    NODUMP_FL = 0x00000040
    NOATIME_FL = 0x00000080
    DIRTY_FL = 0x0000010
    COMPRBLK_FL = 0x00000200
    NOCOMP_FL = 0x00000400
    ENCRYPT_FL = 0x00000800
    BTREE_FL = 0x00001000
    INDEX_FL = 0x00001000
    IMAGIC_FL = 0x00002000
    JOURNAL_DATA_FL = 0x00004000
    NOTAIL_FL = 0x00008000
    DIRSYNC_FL = 0x00010000
    TOPDIR_FL = 0x00020000
    HUGE_FILE_FL = 0x00040000
    EXTENT_FL = 0x00080000
    VERITY_FL = 0x00100000
    EA_INODE_FL = 0x00200000
    EOFBLOCKS_FL = 0x00400000
    NOCOW_FL = 0x00800000
    DAX_FL = 0x02000000
    INLINE_DATA_FL = 0x10000000
    PROJINHERIT_FL = 0x20000000
    CASEFOLD_FL = 0x40000000
    RESERVED_FL = 0x80000000

    FL_USER_VISIBLE = 0x0003DFFF
    FL_USER_MODIFIABLE = 0x000380FF

#end FS

#+
# Higher-level stuff
#-

def _get_fileno(fd, argname = "fd") :
    # common code to allow caller to pass either an integer file
    # descriptor or an object with the usual Python fileno() method
    # that returns such a file descriptor.
    if not isinstance(fd, int) :
        if hasattr(fd, "fileno") :
            fd = fd.fileno()
        else :
            raise TypeError("%s arg must be int fileno or object with fileno() method" % argname)
        #end if
    #end if
    return \
        fd
#end _get_fileno

def _get_path(pathname, argname) :
    # returns a utf-8-encoded representation of pathname.
    if isinstance(pathname, str) :
        c_pathname = pathname.encode()
    elif not isinstance(pathname, (bytes, bytearray)) :
        raise TypeError("%s must be string or bytes" % argname)
    else :
        c_pathname = pathname
    #end if
    return \
        c_pathname
#end _get_path

def _check_sts(sts) :
    if sts < 0 :
        errno = ct.get_errno()
        raise OSError(errno, os.strerror(errno))
    #end if
#end _check_sts

def getflags(fd) :
    flags = ct.c_long()
    _check_sts(libc.ioctl(_get_fileno(fd), FS.IOC_GETFLAGS, ct.byref(flags)))
    return \
        flags.value
#end getflags

def setflags(fd, flags) :
    c_flags = ct.c_long(flags)
    _check_sts(libc.ioctl(_get_fileno(fd), FS.IOC_SETFLAGS, ct.byref(c_flags)))
#end setflags

def getfsxattr(fd) :
    "returns the fsx_ attribute flags as found in </usr/include/linux/fs.h>."
    xattr = FS.xattr()
    _check_sts(libc.ioctl(_get_fileno(fd), FS.IOC_FSGETXATTR, ct.byref(xattr)))
    return \
        xattr
#end getfsxattr

def setfsxattr(fd, *args, **kwargs) :
    "sets new values for the fsx_ attribute flags as found in" \
    " </usr/include/linux/fs.h>. Call this as follows:\n" \
    "\n" \
    "    setfsxattr(fd[, «newattrs»], [«field» = «value», ...])\n" \
    "\n" \
    "where «newattrs» is a FS.xattr struct, and the individual «fields» of" \
    " the FS.xattr struct can also be specified by name. Any fields not" \
    " specified by name keep their value from «newattrs», or are set to" \
    " zero if «newattrs» is not specified. This allows you to selectively" \
    " change certain fields with a call like\n" \
    "\n" \
    "    setfsxattr(fd, getfsxattr(fd), «field» = «value», ...)"
    if len(args) + len(kwargs) == 0 :
        raise TypeError("nothing to do")
    #end if
    if len(args) > 1 :
        raise TypeError("only expecting one positional argument")
    #end if
    if len(args) > 0 :
        xattr = args[0]
        if not isinstance(xattr, FS.xattr) :
            raise TypeError("positional argument is not a FS.xattr struct")
        #end if
    else :
        xattr = FS.xattr()
    #end if
    if (len(args) != 0) == (len(kwargs) != 0) :
        raise TypeError \
          (
            "either pass a positional FS.xattr argument, or"
            " individual field values by keyword"
          )
    #end if
    if len(kwargs) > 0 :
        valid = set(f[0] for f in FS.xattr._fields_ if f[0] != "fsx_pad")
        for field in kwargs :
            if field not in valid :
                raise TypeError("invalid FS.xattr keyword %s" % field)
            #end if
            setattr(xattr, field, kwargs[field])
        #end for
    #end if
    _check_sts(libc.ioctl(_get_fileno(fd), FS.IOC_FSSETXATTR, ct.byref(xattr)))
#end setfsxattr

def open_at(dirfd, pathname, **kwargs) :
    "convenient wrapper around openat2(2) which breaks out fields of open_how" \
    " struct into separate keyword args (flags, mode, resolve). Returns open" \
    " file descriptor on success."
    how = OPENAT2.open_how()
    valid = set(f[0] for f in OPENAT2.open_how._fields_)
    for field in kwargs :
        if field not in valid :
            raise TypeError("invalid OPENAT2 keyword %s" % field)
        #end if
        setattr(how, field, kwargs[field])
    #end for
    res = openat2 \
      (
        _get_fileno(dirfd, "dirfd"),
        _get_path(pathname, "pathname"),
        ct.byref(how),
        ct.sizeof(how)
      )
    _check_sts(res)
    return \
        res
#end open_at

def save_tmpfile(fd, path) :
    "assumes fd was previously created as an anonymous file with O_TMPFILE flag;" \
    " gives it the explicit name path, which must be on the same filesystem" \
    " where it was originally created. This is done following the procedure given" \
    " on the openat(2) man page."
    c_path = _get_path(path)
    tmpfile_path = "/proc/self/fd/%d" % _get_file(fd) # “magic symlink” to name of file with no name
    _check_sts(libc.linkat(AT_FDCWD, tmpfile_path.encode(), AT_FDCWD, c_path, AT_SYMLINK_FOLLOW))
#end save_tmpfile
