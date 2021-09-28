#+
# This module implements a pure-Python wrapper around the
# Linux-specific filesystem attribute functions.
#
#-

import os
import enum
import ctypes as ct
import atexit

libc = ct.CDLL("libc.so.6", use_errno = True)

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

libc.ioctl.argtypes = (ct.c_int, ct.c_ulong, ct.c_void_p)
libc.ioctl.restype = ct.c_int

TBD
