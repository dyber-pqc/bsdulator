/*
 * BSDulator - ABI Translation
 * Translates FreeBSD structures and flags to Linux equivalents
 */

#ifndef BSDULATOR_ABI_H
#define BSDULATOR_ABI_H

#include <stdint.h>
#include <sys/types.h>

/*
 * FreeBSD open() flags
 */
#define FBSD_O_RDONLY       0x0000
#define FBSD_O_WRONLY       0x0001
#define FBSD_O_RDWR         0x0002
#define FBSD_O_ACCMODE      0x0003
#define FBSD_O_NONBLOCK     0x0004
#define FBSD_O_APPEND       0x0008
#define FBSD_O_SHLOCK       0x0010
#define FBSD_O_EXLOCK       0x0020
#define FBSD_O_ASYNC        0x0040
#define FBSD_O_FSYNC        0x0080
#define FBSD_O_SYNC         0x0080
#define FBSD_O_NOFOLLOW     0x0100
#define FBSD_O_CREAT        0x0200
#define FBSD_O_TRUNC        0x0400
#define FBSD_O_EXCL         0x0800
#define FBSD_O_NOCTTY       0x8000
#define FBSD_O_DIRECT       0x00010000
#define FBSD_O_DIRECTORY    0x00020000
#define FBSD_O_EXEC         0x00040000
#define FBSD_O_TTY_INIT     0x00080000
#define FBSD_O_CLOEXEC      0x00100000
#define FBSD_O_VERIFY       0x00200000
#define FBSD_O_PATH         0x00400000
#define FBSD_O_EMPTY_PATH   0x02000000

/*
 * FreeBSD mmap() flags
 */
#define FBSD_MAP_SHARED     0x0001
#define FBSD_MAP_PRIVATE    0x0002
#define FBSD_MAP_FIXED      0x0010
#define FBSD_MAP_RENAME     0x0020
#define FBSD_MAP_NORESERVE  0x0040
#define FBSD_MAP_RESERVED0080 0x0080
#define FBSD_MAP_RESERVED0100 0x0100
#define FBSD_MAP_HASSEMAPHORE 0x0200
#define FBSD_MAP_STACK      0x0400
#define FBSD_MAP_NOSYNC     0x0800
#define FBSD_MAP_ANON       0x1000
#define FBSD_MAP_ANONYMOUS  0x1000
#define FBSD_MAP_NOCORE     0x00020000
#define FBSD_MAP_PREFAULT_READ 0x00040000
#define FBSD_MAP_32BIT      0x00080000
#define FBSD_MAP_GUARD      0x00002000
#define FBSD_MAP_EXCL       0x00004000
#define FBSD_MAP_ALIGNED_SUPER 0x01000000

/*
 * FreeBSD mmap() protection
 */
#define FBSD_PROT_NONE      0x00
#define FBSD_PROT_READ      0x01
#define FBSD_PROT_WRITE     0x02
#define FBSD_PROT_EXEC      0x04

/*
 * FreeBSD signal numbers
 */
#define FBSD_SIGHUP         1
#define FBSD_SIGINT         2
#define FBSD_SIGQUIT        3
#define FBSD_SIGILL         4
#define FBSD_SIGTRAP        5
#define FBSD_SIGABRT        6
#define FBSD_SIGIOT         FBSD_SIGABRT
#define FBSD_SIGEMT         7
#define FBSD_SIGFPE         8
#define FBSD_SIGKILL        9
#define FBSD_SIGBUS         10
#define FBSD_SIGSEGV        11
#define FBSD_SIGSYS         12
#define FBSD_SIGPIPE        13
#define FBSD_SIGALRM        14
#define FBSD_SIGTERM        15
#define FBSD_SIGURG         16
#define FBSD_SIGSTOP        17
#define FBSD_SIGTSTP        18
#define FBSD_SIGCONT        19
#define FBSD_SIGCHLD        20
#define FBSD_SIGTTIN        21
#define FBSD_SIGTTOU        22
#define FBSD_SIGIO          23
#define FBSD_SIGXCPU        24
#define FBSD_SIGXFSZ        25
#define FBSD_SIGVTALRM      26
#define FBSD_SIGPROF        27
#define FBSD_SIGWINCH       28
#define FBSD_SIGINFO        29
#define FBSD_SIGUSR1        30
#define FBSD_SIGUSR2        31
#define FBSD_SIGTHR         32
#define FBSD_SIGLIBRT       33

/*
 * FreeBSD fcntl commands
 */
#define FBSD_F_DUPFD        0
#define FBSD_F_GETFD        1
#define FBSD_F_SETFD        2
#define FBSD_F_GETFL        3
#define FBSD_F_SETFL        4
#define FBSD_F_GETOWN       5
#define FBSD_F_SETOWN       6
#define FBSD_F_OGETLK       7
#define FBSD_F_OSETLK       8
#define FBSD_F_OSETLKW      9
#define FBSD_F_DUP2FD       10
#define FBSD_F_GETLK        11
#define FBSD_F_SETLK        12
#define FBSD_F_SETLKW       13
#define FBSD_F_SETLK_REMOTE 14
#define FBSD_F_READAHEAD    15
#define FBSD_F_RDAHEAD      16
#define FBSD_F_DUPFD_CLOEXEC 17
#define FBSD_F_DUP2FD_CLOEXEC 18
#define FBSD_F_ADD_SEALS    19
#define FBSD_F_GET_SEALS    20
#define FBSD_F_ISUNIONSTACK 21
#define FBSD_F_KINFO        22

/*
 * FreeBSD stat structure (FreeBSD 12+)
 */
typedef struct {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint16_t st_mode;
    int16_t  st_padding0;
    uint32_t st_uid;
    uint32_t st_gid;
    int32_t  st_padding1;
    uint64_t st_rdev;
    int64_t  st_atim_sec;
    int64_t  st_atim_nsec;
    int64_t  st_mtim_sec;
    int64_t  st_mtim_nsec;
    int64_t  st_ctim_sec;
    int64_t  st_ctim_nsec;
    int64_t  st_birthtim_sec;
    int64_t  st_birthtim_nsec;
    int64_t  st_size;
    int64_t  st_blocks;
    int32_t  st_blksize;
    uint32_t st_flags;
    uint64_t st_gen;
    uint64_t st_spare[10];
} fbsd_stat_t;

/*
 * FreeBSD dirent structure
 */
typedef struct {
    uint64_t d_fileno;
    uint64_t d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    uint8_t  d_pad0;
    uint16_t d_namlen;
    uint16_t d_pad1;
    char     d_name[256];
} fbsd_dirent_t;

/*
 * FreeBSD timespec
 */
typedef struct {
    int64_t tv_sec;
    int64_t tv_nsec;
} fbsd_timespec_t;

/*
 * FreeBSD timeval
 */
typedef struct {
    int64_t tv_sec;
    int64_t tv_usec;
} fbsd_timeval_t;

/* Translation functions */

/* Open flags */
int abi_translate_open_flags(int freebsd_flags);
int abi_translate_open_flags_to_freebsd(int linux_flags);

/* mmap flags */
int abi_translate_mmap_flags(int freebsd_flags);
int abi_translate_mmap_prot(int freebsd_prot);

/* mmap alignment tracking (for MAP_ALIGNED support) */
int abi_get_mmap_alignment_shift(int freebsd_flags);
size_t abi_get_pending_mmap_alignment(void);
size_t abi_get_pending_mmap_orig_size(void);
void abi_set_pending_mmap_size(size_t size);
void abi_clear_pending_mmap_alignment(void);

/* Signals */
int abi_translate_signal(int freebsd_sig);
int abi_translate_signal_to_freebsd(int linux_sig);

/* fcntl */
int abi_translate_fcntl_cmd(int freebsd_cmd);

/* stat structure */
int abi_translate_stat_to_freebsd(const void *linux_stat, fbsd_stat_t *freebsd_stat);
int abi_translate_stat_from_freebsd(const fbsd_stat_t *freebsd_stat, void *linux_stat);

/* dirent structure */
int abi_translate_dirent_to_freebsd(const void *linux_dirent, fbsd_dirent_t *freebsd_dirent);
int abi_translate_dirents_to_freebsd(const void *linux_buf, size_t linux_len,
                                     void *freebsd_buf, size_t freebsd_buf_size);

/* AT_ flags for *at syscalls */
int abi_translate_at_flags(int freebsd_flags);

/* errno */
int abi_translate_errno(int linux_errno);
int abi_translate_errno_to_linux(int freebsd_errno);

/* Socket options */
int abi_translate_sockopt_level(int freebsd_level);
int abi_translate_sockopt_name(int level, int freebsd_name);

/* Socket address family */
int abi_translate_socket_family(int freebsd_family);

/* ioctl commands */
unsigned long abi_translate_ioctl_cmd(unsigned long freebsd_cmd);

#endif /* BSDULATOR_ABI_H */