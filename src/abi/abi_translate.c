/*
 * BSDulator - ABI Translation Implementation
 * Translates FreeBSD ABI elements to Linux equivalents
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include "bsdulator.h"
#include "bsdulator/syscall.h"
#include "bsdulator/signal_emul.h"

/*
 * Track pending mmap alignment requirement
 * This is used to post-process mmap results
 */
static __thread size_t pending_mmap_alignment = 0;
static __thread size_t pending_mmap_orig_size = 0;

/*
 * Open flags translation
 */
int abi_translate_open_flags(int freebsd_flags) {
    int linux_flags = 0;
    
    /* Access mode (bottom 2 bits are the same) */
    linux_flags |= (freebsd_flags & FBSD_O_ACCMODE);
    
    /* Standard flags */
    if (freebsd_flags & FBSD_O_NONBLOCK)   linux_flags |= O_NONBLOCK;
    if (freebsd_flags & FBSD_O_APPEND)     linux_flags |= O_APPEND;
    if (freebsd_flags & FBSD_O_CREAT)      linux_flags |= O_CREAT;
    if (freebsd_flags & FBSD_O_TRUNC)      linux_flags |= O_TRUNC;
    if (freebsd_flags & FBSD_O_EXCL)       linux_flags |= O_EXCL;
    if (freebsd_flags & FBSD_O_NOCTTY)     linux_flags |= O_NOCTTY;
    if (freebsd_flags & FBSD_O_SYNC)       linux_flags |= O_SYNC;
    if (freebsd_flags & FBSD_O_ASYNC)      linux_flags |= O_ASYNC;
    if (freebsd_flags & FBSD_O_NOFOLLOW)   linux_flags |= O_NOFOLLOW;
    if (freebsd_flags & FBSD_O_DIRECTORY)  linux_flags |= O_DIRECTORY;
    if (freebsd_flags & FBSD_O_CLOEXEC)    linux_flags |= O_CLOEXEC;
    
#ifdef O_DIRECT
    if (freebsd_flags & FBSD_O_DIRECT)     linux_flags |= O_DIRECT;
#endif

#ifdef O_PATH
    if (freebsd_flags & FBSD_O_PATH)       linux_flags |= O_PATH;
#endif

    /* FreeBSD-specific flags that have no Linux equivalent */
    if (freebsd_flags & FBSD_O_SHLOCK) {
        BSD_TRACE("O_SHLOCK flag ignored (no Linux equivalent)");
    }
    if (freebsd_flags & FBSD_O_EXLOCK) {
        BSD_TRACE("O_EXLOCK flag ignored (no Linux equivalent)");
    }
    
    return linux_flags;
}

int abi_translate_open_flags_to_freebsd(int linux_flags) {
    int freebsd_flags = 0;
    
    freebsd_flags |= (linux_flags & O_ACCMODE);
    
    if (linux_flags & O_NONBLOCK)   freebsd_flags |= FBSD_O_NONBLOCK;
    if (linux_flags & O_APPEND)     freebsd_flags |= FBSD_O_APPEND;
    if (linux_flags & O_CREAT)      freebsd_flags |= FBSD_O_CREAT;
    if (linux_flags & O_TRUNC)      freebsd_flags |= FBSD_O_TRUNC;
    if (linux_flags & O_EXCL)       freebsd_flags |= FBSD_O_EXCL;
    if (linux_flags & O_NOCTTY)     freebsd_flags |= FBSD_O_NOCTTY;
    if (linux_flags & O_SYNC)       freebsd_flags |= FBSD_O_SYNC;
    if (linux_flags & O_ASYNC)      freebsd_flags |= FBSD_O_ASYNC;
    if (linux_flags & O_NOFOLLOW)   freebsd_flags |= FBSD_O_NOFOLLOW;
    if (linux_flags & O_DIRECTORY)  freebsd_flags |= FBSD_O_DIRECTORY;
    if (linux_flags & O_CLOEXEC)    freebsd_flags |= FBSD_O_CLOEXEC;
    
    return freebsd_flags;
}

/*
 * Extract MAP_ALIGNED shift value from FreeBSD mmap flags
 * Returns 0 if no alignment requested, otherwise the shift (12-29)
 */
int abi_get_mmap_alignment_shift(int freebsd_flags) {
    /* FreeBSD MAP_ALIGNED(n) = (n << 24), stored in bits 24-29 */
    int align_shift = (freebsd_flags >> 24) & 0x3F;
    return align_shift;
}

/*
 * Get pending mmap alignment requirement (in bytes)
 */
size_t abi_get_pending_mmap_alignment(void) {
    return pending_mmap_alignment;
}

/*
 * Get pending mmap original size
 */
size_t abi_get_pending_mmap_orig_size(void) {
    return pending_mmap_orig_size;
}

/*
 * Clear pending mmap alignment tracking
 */
void abi_clear_pending_mmap_alignment(void) {
    pending_mmap_alignment = 0;
    pending_mmap_orig_size = 0;
}

/*
 * mmap flags translation
 * Also tracks alignment requirement for post-processing
 */
int abi_translate_mmap_flags(int freebsd_flags) {
    int linux_flags = 0;
    
    if (freebsd_flags & FBSD_MAP_SHARED)    linux_flags |= MAP_SHARED;
    if (freebsd_flags & FBSD_MAP_PRIVATE)   linux_flags |= MAP_PRIVATE;
    if (freebsd_flags & FBSD_MAP_FIXED)     linux_flags |= MAP_FIXED;
    if (freebsd_flags & FBSD_MAP_ANONYMOUS) linux_flags |= MAP_ANONYMOUS;
    
#ifdef MAP_STACK
    if (freebsd_flags & FBSD_MAP_STACK)     linux_flags |= MAP_STACK;
#endif

#ifdef MAP_32BIT
    if (freebsd_flags & FBSD_MAP_32BIT)     linux_flags |= MAP_32BIT;
#endif

#ifdef MAP_NORESERVE
    if (freebsd_flags & FBSD_MAP_NORESERVE) linux_flags |= MAP_NORESERVE;
#endif
    
    /* FreeBSD MAP_ALIGNED(n) = (n << 24)
     * This requests alignment to 2^n bytes.
     * Linux doesn't have MAP_ALIGNED, so we need to handle this differently.
     * We track the alignment requirement and fix it up after mmap returns.
     */
    int align_shift = (freebsd_flags >> 24) & 0x3F;  /* Top 6 bits after stripping */
    if (align_shift > 0) {
        size_t alignment = (size_t)1 << align_shift;
        BSD_TRACE("mmap: MAP_ALIGNED(%d) = %zu byte alignment requested",
                  align_shift, alignment);
        pending_mmap_alignment = alignment;
    } else {
        pending_mmap_alignment = 0;
    }
    pending_mmap_orig_size = 0;  /* Will be set by caller */
    
    /* FreeBSD-specific flags with no Linux equivalent */
    if (freebsd_flags & FBSD_MAP_NOSYNC) {
        BSD_TRACE("MAP_NOSYNC flag ignored");
    }
    if (freebsd_flags & FBSD_MAP_NOCORE) {
        BSD_TRACE("MAP_NOCORE flag ignored");
    }
    
    /* Linux requires MAP_SHARED or MAP_PRIVATE */
    if (!(linux_flags & (MAP_SHARED | MAP_PRIVATE))) {
        linux_flags |= MAP_PRIVATE;
        BSD_TRACE("mmap: adding MAP_PRIVATE (Linux requires SHARED or PRIVATE)");
    }
    BSD_TRACE("mmap flags: FreeBSD 0x%x -> Linux 0x%x", freebsd_flags, linux_flags);
    
    return linux_flags;
}

/*
 * Set the original mmap size (for alignment fixup calculation)
 */
void abi_set_pending_mmap_size(size_t size) {
    pending_mmap_orig_size = size;
}

int abi_translate_mmap_prot(int freebsd_prot) {
    /* PROT_* values are the same on FreeBSD and Linux */
    int linux_prot = 0;
    
    if (freebsd_prot & FBSD_PROT_READ)  linux_prot |= PROT_READ;
    if (freebsd_prot & FBSD_PROT_WRITE) linux_prot |= PROT_WRITE;
    if (freebsd_prot & FBSD_PROT_EXEC)  linux_prot |= PROT_EXEC;
    
    if (freebsd_prot == FBSD_PROT_NONE) linux_prot = PROT_NONE;
    
    return linux_prot;
}

/*
 * Signal number translation (see src/signal/signal_emul.c for the table,
 * which also covers real-time signals). Unknown signals pass through.
 */
int abi_translate_signal(int freebsd_sig) {
    int l = sig_fbsd_to_linux(freebsd_sig);
    return l ? l : freebsd_sig;
}

int abi_translate_signal_to_freebsd(int linux_sig) {
    int f = sig_linux_to_fbsd(linux_sig);
    return f ? f : linux_sig;
}

/*
 * fcntl command translation
 */
int abi_translate_fcntl_cmd(int freebsd_cmd) {
    /* Most fcntl commands are the same between FreeBSD and Linux */
    /* Only translate the ones that differ */
    switch (freebsd_cmd) {
        /* These are the same on both systems */
        case FBSD_F_DUPFD:
        case FBSD_F_GETFD:
        case FBSD_F_SETFD:
        case FBSD_F_GETFL:
        case FBSD_F_SETFL:
        case FBSD_F_GETOWN:
        case FBSD_F_SETOWN:
        case FBSD_F_GETLK:
        case FBSD_F_SETLK:
        case FBSD_F_SETLKW:
            return freebsd_cmd;
            
        /* FreeBSD-specific commands */
        case FBSD_F_DUP2FD:
            /* No direct Linux equivalent - would need emulation */
            BSD_TRACE("fcntl F_DUP2FD not directly supported");
            return -1;
            
        case FBSD_F_DUPFD_CLOEXEC:
            /* FreeBSD F_DUPFD_CLOEXEC = 17, Linux = 1030 (F_LINUX_SPECIFIC_BASE + 6) */
            BSD_TRACE("fcntl F_DUPFD_CLOEXEC: FreeBSD 17 -> Linux 1030");
            return 1030;
            
        default:
            return freebsd_cmd;
    }
}

/*
 * errno translation (Linux <-> FreeBSD)
 *
 * Values 1-34 are the same on both systems except 11: Linux EAGAIN is 11
 * and EDEADLK 35, FreeBSD the other way round. From 35 up nearly all
 * differ. Values are from Linux asm-generic/errno*.h and FreeBSD
 * sys/sys/errno.h. Unknown values pass through.
 */
int abi_translate_errno(int linux_errno) {
    switch (linux_errno) {
        case 11: return 35;   /* EAGAIN / EWOULDBLOCK */
        case 35: return 11;   /* EDEADLK */
        case 36: return 63;   /* ENAMETOOLONG */
        case 37: return 77;   /* ENOLCK */
        case 38: return 78;   /* ENOSYS */
        case 39: return 66;   /* ENOTEMPTY */
        case 40: return 62;   /* ELOOP */
        case 42: return 83;   /* ENOMSG */
        case 43: return 82;   /* EIDRM */
        case 61: return 87;   /* ENODATA -> ENOATTR */
        case 66: return 71;   /* EREMOTE */
        case 67: return 91;   /* ENOLINK */
        case 71: return 92;   /* EPROTO */
        case 72: return 90;   /* EMULTIHOP */
        case 74: return 89;   /* EBADMSG */
        case 75: return 84;   /* EOVERFLOW */
        case 84: return 86;   /* EILSEQ */
        case 87: return 68;   /* EUSERS */
        case 88: return 38;   /* ENOTSOCK */
        case 89: return 39;   /* EDESTADDRREQ */
        case 90: return 40;   /* EMSGSIZE */
        case 91: return 41;   /* EPROTOTYPE */
        case 92: return 42;   /* ENOPROTOOPT */
        case 93: return 43;   /* EPROTONOSUPPORT */
        case 94: return 44;   /* ESOCKTNOSUPPORT */
        case 95: return 45;   /* EOPNOTSUPP / ENOTSUP */
        case 96: return 46;   /* EPFNOSUPPORT */
        case 97: return 47;   /* EAFNOSUPPORT */
        case 98: return 48;   /* EADDRINUSE */
        case 99: return 49;   /* EADDRNOTAVAIL */
        case 100: return 50;  /* ENETDOWN */
        case 101: return 51;  /* ENETUNREACH */
        case 102: return 52;  /* ENETRESET */
        case 103: return 53;  /* ECONNABORTED */
        case 104: return 54;  /* ECONNRESET */
        case 105: return 55;  /* ENOBUFS */
        case 106: return 56;  /* EISCONN */
        case 107: return 57;  /* ENOTCONN */
        case 108: return 58;  /* ESHUTDOWN */
        case 109: return 59;  /* ETOOMANYREFS */
        case 110: return 60;  /* ETIMEDOUT */
        case 111: return 61;  /* ECONNREFUSED */
        case 112: return 64;  /* EHOSTDOWN */
        case 113: return 65;  /* EHOSTUNREACH */
        case 114: return 37;  /* EALREADY */
        case 115: return 36;  /* EINPROGRESS */
        case 116: return 70;  /* ESTALE */
        case 122: return 69;  /* EDQUOT */
        case 125: return 85;  /* ECANCELED */
        case 130: return 96;  /* EOWNERDEAD */
        case 131: return 95;  /* ENOTRECOVERABLE */
        default: return linux_errno;
    }
}

int abi_translate_errno_to_linux(int freebsd_errno) {
    switch (freebsd_errno) {
        case 11: return 35;   /* EDEADLK */
        case 35: return 11;   /* EAGAIN / EWOULDBLOCK */
        case 36: return 115;  /* EINPROGRESS */
        case 37: return 114;  /* EALREADY */
        case 38: return 88;   /* ENOTSOCK */
        case 39: return 89;   /* EDESTADDRREQ */
        case 40: return 90;   /* EMSGSIZE */
        case 41: return 91;   /* EPROTOTYPE */
        case 42: return 92;   /* ENOPROTOOPT */
        case 43: return 93;   /* EPROTONOSUPPORT */
        case 44: return 94;   /* ESOCKTNOSUPPORT */
        case 45: return 95;   /* EOPNOTSUPP / ENOTSUP */
        case 46: return 96;   /* EPFNOSUPPORT */
        case 47: return 97;   /* EAFNOSUPPORT */
        case 48: return 98;   /* EADDRINUSE */
        case 49: return 99;   /* EADDRNOTAVAIL */
        case 50: return 100;  /* ENETDOWN */
        case 51: return 101;  /* ENETUNREACH */
        case 52: return 102;  /* ENETRESET */
        case 53: return 103;  /* ECONNABORTED */
        case 54: return 104;  /* ECONNRESET */
        case 55: return 105;  /* ENOBUFS */
        case 56: return 106;  /* EISCONN */
        case 57: return 107;  /* ENOTCONN */
        case 58: return 108;  /* ESHUTDOWN */
        case 59: return 109;  /* ETOOMANYREFS */
        case 60: return 110;  /* ETIMEDOUT */
        case 61: return 111;  /* ECONNREFUSED */
        case 62: return 40;   /* ELOOP */
        case 63: return 36;   /* ENAMETOOLONG */
        case 64: return 112;  /* EHOSTDOWN */
        case 65: return 113;  /* EHOSTUNREACH */
        case 66: return 39;   /* ENOTEMPTY */
        case 68: return 87;   /* EUSERS */
        case 69: return 122;  /* EDQUOT */
        case 70: return 116;  /* ESTALE */
        case 71: return 66;   /* EREMOTE */
        case 77: return 37;   /* ENOLCK */
        case 78: return 38;   /* ENOSYS */
        case 82: return 43;   /* EIDRM */
        case 83: return 42;   /* ENOMSG */
        case 84: return 75;   /* EOVERFLOW */
        case 85: return 125;  /* ECANCELED */
        case 86: return 84;   /* EILSEQ */
        case 89: return 74;   /* EBADMSG */
        case 90: return 72;   /* EMULTIHOP */
        case 91: return 67;   /* ENOLINK */
        case 92: return 71;   /* EPROTO */
        case 95: return 131;  /* ENOTRECOVERABLE */
        case 96: return 130;  /* EOWNERDEAD */
        default: return freebsd_errno;
    }
}

/*
 * Translate Linux stat structure to FreeBSD format
 * Called after fstat/fstatat/stat syscalls return successfully
 */
int abi_translate_stat_to_freebsd(const void *linux_stat, fbsd_stat_t *fbsd) {
    const uint8_t *ls = (const uint8_t *)linux_stat;
    
    /* Clear the FreeBSD stat structure first */
    memset(fbsd, 0, sizeof(fbsd_stat_t));
    
    /* Linux struct stat offsets (x86_64):
     * 0:  st_dev (8)
     * 8:  st_ino (8)
     * 16: st_nlink (8)
     * 24: st_mode (4)
     * 28: st_uid (4)
     * 32: st_gid (4)
     * 36: __pad0 (4)
     * 40: st_rdev (8)
     * 48: st_size (8)
     * 56: st_blksize (8)
     * 64: st_blocks (8)
     * 72: st_atim (16)
     * 88: st_mtim (16)
     * 104: st_ctim (16)
     */
    
    /* Copy fields with proper offset translation */
    memcpy(&fbsd->st_dev, ls + 0, 8);
    memcpy(&fbsd->st_ino, ls + 8, 8);
    memcpy(&fbsd->st_nlink, ls + 16, 8);
    
    /* st_mode: Linux is 4 bytes at offset 24, FreeBSD is 2 bytes */
    uint32_t linux_mode;
    memcpy(&linux_mode, ls + 24, 4);
    fbsd->st_mode = (uint16_t)(linux_mode & 0xFFFF);
    
    memcpy(&fbsd->st_uid, ls + 28, 4);
    memcpy(&fbsd->st_gid, ls + 32, 4);
    memcpy(&fbsd->st_rdev, ls + 40, 8);
    
    /* Times: Linux at 72/88/104, FreeBSD expects timespec at different offsets */
    memcpy(&fbsd->st_atim_sec, ls + 72, 8);
    memcpy(&fbsd->st_atim_nsec, ls + 80, 8);
    memcpy(&fbsd->st_mtim_sec, ls + 88, 8);
    memcpy(&fbsd->st_mtim_nsec, ls + 96, 8);
    memcpy(&fbsd->st_ctim_sec, ls + 104, 8);
    memcpy(&fbsd->st_ctim_nsec, ls + 112, 8);
    
    /* birthtim - Linux doesn't have this, use ctim as fallback */
    fbsd->st_birthtim_sec = fbsd->st_ctim_sec;
    fbsd->st_birthtim_nsec = fbsd->st_ctim_nsec;
    
    /* st_size: Linux at 48 */
    memcpy(&fbsd->st_size, ls + 48, 8);
    
    /* st_blocks: Linux at 64 */
    memcpy(&fbsd->st_blocks, ls + 64, 8);
    
    /* st_blksize: Linux at 56 (8 bytes), FreeBSD expects 4 bytes */
    int64_t blksize;
    memcpy(&blksize, ls + 56, 8);
    fbsd->st_blksize = (int32_t)blksize;
    
    /* st_flags and st_gen - FreeBSD specific, set to 0 */
    fbsd->st_flags = 0;
    fbsd->st_gen = 0;
    
    return 0;
}

/* Legacy wrapper for old function name */
int abi_translate_stat(const void *linux_stat, void *freebsd_stat) {
    return abi_translate_stat_to_freebsd(linux_stat, (fbsd_stat_t *)freebsd_stat);
}

/*
 * Translate FreeBSD stat structure to Linux (reverse direction)
 */
int abi_translate_stat_from_freebsd(const fbsd_stat_t *fbsd, void *linux_stat) {
    uint8_t *ls = (uint8_t *)linux_stat;
    
    memset(ls, 0, 144);
    
    memcpy(ls + 0, &fbsd->st_dev, 8);
    memcpy(ls + 8, &fbsd->st_ino, 8);
    memcpy(ls + 16, &fbsd->st_nlink, 8);
    
    uint32_t linux_mode = fbsd->st_mode;
    memcpy(ls + 24, &linux_mode, 4);
    
    memcpy(ls + 28, &fbsd->st_uid, 4);
    memcpy(ls + 32, &fbsd->st_gid, 4);
    memcpy(ls + 40, &fbsd->st_rdev, 8);
    memcpy(ls + 48, &fbsd->st_size, 8);
    
    int64_t blksize = fbsd->st_blksize;
    memcpy(ls + 56, &blksize, 8);
    memcpy(ls + 64, &fbsd->st_blocks, 8);
    
    memcpy(ls + 72, &fbsd->st_atim_sec, 8);
    memcpy(ls + 80, &fbsd->st_atim_nsec, 8);
    memcpy(ls + 88, &fbsd->st_mtim_sec, 8);
    memcpy(ls + 96, &fbsd->st_mtim_nsec, 8);
    memcpy(ls + 104, &fbsd->st_ctim_sec, 8);
    memcpy(ls + 112, &fbsd->st_ctim_nsec, 8);
    
    return 0;
}

/* Legacy wrapper */
int abi_translate_stat_to_linux(const void *freebsd_stat, void *linux_stat) {
    return abi_translate_stat_from_freebsd((const fbsd_stat_t *)freebsd_stat, linux_stat);
}

/*
 * Translate FreeBSD AT_ flags to Linux equivalents
 * Used by fstatat, faccessat, fchmodat, fchownat, etc.
 */
int abi_translate_at_flags(int freebsd_flags) {
    int linux_flags = 0;
    
    /* FreeBSD -> Linux AT_ flag mapping:
     * FreeBSD AT_EACCESS          0x0100 -> Linux AT_EACCESS       0x0200
     * FreeBSD AT_SYMLINK_NOFOLLOW 0x0200 -> Linux AT_SYMLINK_NOFOLLOW 0x0100
     * FreeBSD AT_SYMLINK_FOLLOW   0x0400 -> Linux AT_SYMLINK_FOLLOW   0x0400
     * FreeBSD AT_REMOVEDIR        0x0800 -> Linux AT_REMOVEDIR        0x0200
     * FreeBSD AT_EMPTY_PATH       0x4000 -> Linux AT_EMPTY_PATH       0x1000
     */
    
    if (freebsd_flags & 0x0100) /* FreeBSD AT_EACCESS */
        linux_flags |= 0x0200;  /* Linux AT_EACCESS */
    
    if (freebsd_flags & 0x0200) /* FreeBSD AT_SYMLINK_NOFOLLOW */
        linux_flags |= 0x0100;  /* Linux AT_SYMLINK_NOFOLLOW */
    
    if (freebsd_flags & 0x0400) /* FreeBSD AT_SYMLINK_FOLLOW */
        linux_flags |= 0x0400;  /* Linux AT_SYMLINK_FOLLOW (same) */
    
    if (freebsd_flags & 0x0800) /* FreeBSD AT_REMOVEDIR */
        linux_flags |= 0x0200;  /* Linux AT_REMOVEDIR */
    
    if (freebsd_flags & 0x4000) /* FreeBSD AT_EMPTY_PATH */
        linux_flags |= 0x1000;  /* Linux AT_EMPTY_PATH */

    return linux_flags;
}

/*
 * The flag argument's position differs between *at syscalls:
 *   fstatat(fd, path, sb, flag)          faccessat(fd, path, mode, flag)
 *   fchmodat(fd, path, mode, flag)       utimensat(fd, path, times, flag)
 *   fchownat(fd, path, uid, gid, flag)   linkat(fd1, p1, fd2, p2, flag)
 *   unlinkat(fd, path, flag)
 */
/* tv_nsec markers in utimensat/futimens times: FreeBSD UTIME_NOW -1,
 * UTIME_OMIT -2; Linux ((1 << 30) - 1) and ((1 << 30) - 2) */
long abi_utime_nsec_to_linux(long nsec) {
    if (nsec == -1) return (1L << 30) - 1;
    if (nsec == -2) return (1L << 30) - 2;
    return nsec;
}

int abi_at_flags_arg(int freebsd_nr) {
    switch (freebsd_nr) {
        case FBSD_SYS_unlinkat:
            return 2;
        case FBSD_SYS_fstatat:
        case FBSD_SYS_faccessat:
        case FBSD_SYS_fchmodat:
        case FBSD_SYS_utimensat:
            return 3;
        case FBSD_SYS_fchownat:
        case FBSD_SYS_linkat:
            return 4;
        default:
            return -1;
    }
}

/*
 * Translate a single Linux dirent64 to FreeBSD dirent
 */
int abi_translate_dirent_to_freebsd(const void *linux_dirent, fbsd_dirent_t *freebsd_dirent) {
    const uint8_t *ld = (const uint8_t *)linux_dirent;
    
    /* Linux dirent64 layout:
     * offset 0:  uint64_t d_ino
     * offset 8:  int64_t  d_off  
     * offset 16: uint16_t d_reclen
     * offset 18: uint8_t  d_type
     * offset 19: char     d_name[]
     */
    
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    
    memcpy(&d_ino, ld + 0, 8);
    memcpy(&d_off, ld + 8, 8);
    memcpy(&d_reclen, ld + 16, 2);
    d_type = *(ld + 18);
    const char *d_name = (const char *)(ld + 19);
    
    /* Calculate name length */
    size_t namelen = strlen(d_name);
    if (namelen > 255) namelen = 255;
    
    /* Fill FreeBSD dirent */
    memset(freebsd_dirent, 0, sizeof(fbsd_dirent_t));
    freebsd_dirent->d_fileno = d_ino;
    freebsd_dirent->d_off = (uint64_t)d_off;
    freebsd_dirent->d_type = d_type;
    freebsd_dirent->d_namlen = (uint16_t)namelen;
    
    /* Calculate FreeBSD reclen: header (24 bytes) + name + null, aligned to 8 */
    size_t fbsd_reclen = 24 + namelen + 1;
    fbsd_reclen = (fbsd_reclen + 7) & ~7;
    freebsd_dirent->d_reclen = (uint16_t)fbsd_reclen;
    
    /* Copy name */
    memcpy(freebsd_dirent->d_name, d_name, namelen);
    freebsd_dirent->d_name[namelen] = '\0';
    
    return (int)fbsd_reclen;
}

/*
 * Translate Linux dirent64 buffer to FreeBSD dirent buffer
 * Returns: number of bytes written to FreeBSD buffer, or -1 on error
 */
int abi_translate_dirents_to_freebsd(const void *linux_buf, size_t linux_len,
                                     void *freebsd_buf, size_t freebsd_buf_size) {
    const uint8_t *linux_ptr = (const uint8_t *)linux_buf;
    uint8_t *fbsd_ptr = (uint8_t *)freebsd_buf;
    size_t linux_offset = 0;
    size_t fbsd_offset = 0;
    
    while (linux_offset < linux_len) {
        /* Linux dirent64 layout:
         * offset 0:  uint64_t d_ino
         * offset 8:  int64_t  d_off  
         * offset 16: uint16_t d_reclen
         * offset 18: uint8_t  d_type
         * offset 19: char     d_name[]
         */
        const uint8_t *linux_ent = linux_ptr + linux_offset;
        
        uint64_t d_ino;
        int64_t d_off;
        uint16_t d_reclen;
        uint8_t d_type;
        
        memcpy(&d_ino, linux_ent + 0, 8);
        memcpy(&d_off, linux_ent + 8, 8);
        memcpy(&d_reclen, linux_ent + 16, 2);
        d_type = *(linux_ent + 18);
        const char *d_name = (const char *)(linux_ent + 19);
        
        /* Sanity check */
        if (d_reclen == 0 || d_reclen > linux_len - linux_offset) {
            break;
        }
        
        /* Calculate name length */
        size_t namelen = strlen(d_name);
        if (namelen > 255) namelen = 255;
        
        /* FreeBSD dirent size: fixed header (24 bytes) + name + null + padding to 8 bytes */
        size_t fbsd_reclen = 24 + namelen + 1;
        fbsd_reclen = (fbsd_reclen + 7) & ~7;  /* Align to 8 bytes */
        
        /* Check if we have space */
        if (fbsd_offset + fbsd_reclen > freebsd_buf_size) {
            break;
        }
        
        /* Write FreeBSD dirent
         * FreeBSD dirent layout:
         * offset 0:  uint64_t d_fileno
         * offset 8:  uint64_t d_off
         * offset 16: uint16_t d_reclen
         * offset 18: uint8_t  d_type
         * offset 19: uint8_t  d_pad0
         * offset 20: uint16_t d_namlen
         * offset 22: uint16_t d_pad1
         * offset 24: char     d_name[]
         */
        uint8_t *fbsd_ent = fbsd_ptr + fbsd_offset;
        
        /* Zero the entry first */
        memset(fbsd_ent, 0, fbsd_reclen);
        
        /* Copy fields */
        memcpy(fbsd_ent + 0, &d_ino, 8);                           /* d_fileno */
        uint64_t fbsd_off = (uint64_t)d_off;
        memcpy(fbsd_ent + 8, &fbsd_off, 8);                        /* d_off */
        uint16_t fbsd_reclen16 = (uint16_t)fbsd_reclen;
        memcpy(fbsd_ent + 16, &fbsd_reclen16, 2);                  /* d_reclen */
        *(fbsd_ent + 18) = d_type;                                 /* d_type */
        *(fbsd_ent + 19) = 0;                                      /* d_pad0 */
        uint16_t namlen16 = (uint16_t)namelen;
        memcpy(fbsd_ent + 20, &namlen16, 2);                       /* d_namlen */
        /* d_pad1 at offset 22 is already zero from memset */
        
        /* Copy name */
        memcpy(fbsd_ent + 24, d_name, namelen);
        *(fbsd_ent + 24 + namelen) = '\0';
        
        linux_offset += d_reclen;
        fbsd_offset += fbsd_reclen;
    }
    
    return (int)fbsd_offset;
}