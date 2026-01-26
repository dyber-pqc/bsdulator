/*
 * BSDulator - FreeBSD ELF Loader
 * Detects and loads FreeBSD ELF binaries
 */

#ifndef BSDULATOR_LOADER_H
#define BSDULATOR_LOADER_H

#include <stdint.h>
#include <stdbool.h>
#include <elf.h>

/* ELF OS/ABI values - only define if not already defined in elf.h */
#ifndef ELFOSABI_NONE
#define ELFOSABI_NONE       0
#endif
#ifndef ELFOSABI_SYSV
#define ELFOSABI_SYSV       0
#endif
#ifndef ELFOSABI_HPUX
#define ELFOSABI_HPUX       1
#endif
#ifndef ELFOSABI_NETBSD
#define ELFOSABI_NETBSD     2
#endif
#ifndef ELFOSABI_LINUX
#define ELFOSABI_LINUX      3
#endif
#ifndef ELFOSABI_GNU
#define ELFOSABI_GNU        3
#endif
#ifndef ELFOSABI_SOLARIS
#define ELFOSABI_SOLARIS    6
#endif
#ifndef ELFOSABI_AIX
#define ELFOSABI_AIX        7
#endif
#ifndef ELFOSABI_IRIX
#define ELFOSABI_IRIX       8
#endif
#ifndef ELFOSABI_FREEBSD
#define ELFOSABI_FREEBSD    9
#endif
#ifndef ELFOSABI_TRU64
#define ELFOSABI_TRU64      10
#endif
#ifndef ELFOSABI_MODESTO
#define ELFOSABI_MODESTO    11
#endif
#ifndef ELFOSABI_OPENBSD
#define ELFOSABI_OPENBSD    12
#endif
#ifndef ELFOSABI_ARM
#define ELFOSABI_ARM        97
#endif
#ifndef ELFOSABI_STANDALONE
#define ELFOSABI_STANDALONE 255
#endif

/* Binary type detection result */
typedef enum {
    BINARY_UNKNOWN = 0,
    BINARY_FREEBSD,
    BINARY_LINUX,
    BINARY_NETBSD,
    BINARY_OPENBSD,
    BINARY_OTHER
} binary_os_t;

/* Binary linking type */
typedef enum {
    LINK_UNKNOWN = 0,
    LINK_STATIC,
    LINK_DYNAMIC
} binary_link_t;

/* Binary architecture */
typedef enum {
    ARCH_UNKNOWN = 0,
    ARCH_X86,
    ARCH_X86_64,
    ARCH_ARM,
    ARCH_AARCH64,
    ARCH_OTHER
} binary_arch_t;

/* Detailed binary information */
typedef struct {
    const char *path;           /* Path to binary */
    binary_os_t os_type;        /* FreeBSD, Linux, etc. */
    binary_link_t link_type;    /* Static or dynamic */
    binary_arch_t arch;         /* Architecture */
    bool is_64bit;              /* 64-bit binary? */
    uint64_t entry_point;       /* Entry point address */
    char interp[256];           /* Dynamic linker path (if dynamic) */
    
    /* ELF header info */
    uint16_t e_type;            /* Object file type */
    uint16_t e_machine;         /* Architecture */
    uint32_t e_flags;           /* Processor-specific flags */
    
    /* Program header info */
    uint64_t phdr_addr;         /* Program header address */
    uint16_t phdr_num;          /* Number of program headers */
    uint16_t phdr_size;         /* Size of program header entry */
    
    /* Section header info */
    uint64_t shdr_addr;         /* Section header address */
    uint16_t shdr_num;          /* Number of section headers */
    uint16_t shdr_size;         /* Size of section header entry */
} binary_info_t;

/* Check if file is a valid ELF binary */
bool loader_is_elf(const char *path);

/* Check if file is a FreeBSD ELF binary */
bool loader_is_freebsd_elf(const char *path);

/* Get detailed binary information */
int loader_get_info(const char *path, binary_info_t *info);

/* Print binary information */
void loader_print_info(const binary_info_t *info);

/* Check if binary is compatible with BSDulator */
bool loader_is_compatible(const binary_info_t *info);

/* Get string representation of OS type */
const char *loader_os_name(binary_os_t os);

/* Get string representation of architecture */
const char *loader_arch_name(binary_arch_t arch);

/* Get FreeBSD dynamic linker path */
const char *loader_get_freebsd_interp(void);

/* Prepare environment for FreeBSD binary execution */
int loader_prepare_env(const binary_info_t *info, char ***envp);

#endif /* BSDULATOR_LOADER_H */
