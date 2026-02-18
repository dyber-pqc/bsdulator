/*
 * BSDulator - FreeBSD ELF Loader
 * Detects FreeBSD binaries and extracts information
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <errno.h>
#include "bsdulator.h"

/* ELF machine types - only define if not already defined */
#ifndef EM_386
#define EM_386      3
#endif
#ifndef EM_X86_64
#define EM_X86_64   62
#endif
#ifndef EM_ARM
#define EM_ARM      40
#endif
#ifndef EM_AARCH64
#define EM_AARCH64  183
#endif

bool loader_is_elf(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    
    unsigned char magic[4];
    bool is_elf = false;
    
    if (read(fd, magic, 4) == 4) {
        is_elf = (magic[0] == ELFMAG0 &&
                  magic[1] == ELFMAG1 &&
                  magic[2] == ELFMAG2 &&
                  magic[3] == ELFMAG3);
    }
    
    close(fd);
    return is_elf;
}

bool loader_is_freebsd_elf(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    
    unsigned char ident[EI_NIDENT];
    bool is_freebsd = false;
    
    if (read(fd, ident, EI_NIDENT) == EI_NIDENT) {
        /* Check ELF magic */
        if (ident[EI_MAG0] == ELFMAG0 &&
            ident[EI_MAG1] == ELFMAG1 &&
            ident[EI_MAG2] == ELFMAG2 &&
            ident[EI_MAG3] == ELFMAG3) {
            /* Check OS/ABI */
            is_freebsd = (ident[EI_OSABI] == ELFOSABI_FREEBSD);
        }
    }
    
    close(fd);
    return is_freebsd;
}

/* Helper to determine OS from ELF OSABI byte */
static binary_os_t osabi_to_os_type(unsigned char osabi) {
    switch (osabi) {
        case ELFOSABI_FREEBSD:
            return BINARY_FREEBSD;
        case ELFOSABI_NETBSD:
            return BINARY_NETBSD;
        case ELFOSABI_OPENBSD:
            return BINARY_OPENBSD;
        case 0:  /* ELFOSABI_NONE / ELFOSABI_SYSV */
            /* Could be Linux or generic Unix - assume Linux */
            return BINARY_LINUX;
        case 3:  /* ELFOSABI_GNU / ELFOSABI_LINUX */
            return BINARY_LINUX;
        default:
            return BINARY_OTHER;
    }
}

int loader_get_info(const char *path, binary_info_t *info) {
    if (!info) {
        return -1;
    }
    
    memset(info, 0, sizeof(*info));
    info->path = path;
    info->os_type = BINARY_UNKNOWN;
    info->link_type = LINK_UNKNOWN;
    info->arch = ARCH_UNKNOWN;
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        BSD_ERROR("Cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    
    /* Read ELF identification */
    unsigned char ident[EI_NIDENT];
    if (read(fd, ident, EI_NIDENT) != EI_NIDENT) {
        BSD_ERROR("Cannot read ELF ident from %s", path);
        close(fd);
        return -1;
    }
    
    /* Check ELF magic */
    if (ident[EI_MAG0] != ELFMAG0 ||
        ident[EI_MAG1] != ELFMAG1 ||
        ident[EI_MAG2] != ELFMAG2 ||
        ident[EI_MAG3] != ELFMAG3) {
        BSD_ERROR("%s is not an ELF file", path);
        close(fd);
        return -1;
    }
    
    /* Determine 32/64 bit */
    info->is_64bit = (ident[EI_CLASS] == ELFCLASS64);
    
    /* Determine OS type using helper function to avoid duplicate cases */
    info->os_type = osabi_to_os_type(ident[EI_OSABI]);
    
    /* Seek back to beginning for full header */
    lseek(fd, 0, SEEK_SET);
    
    if (info->is_64bit) {
        Elf64_Ehdr ehdr;
        if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
            BSD_ERROR("Cannot read ELF header from %s", path);
            close(fd);
            return -1;
        }
        
        /* Architecture */
        switch (ehdr.e_machine) {
            case EM_X86_64:
                info->arch = ARCH_X86_64;
                break;
            case EM_386:
                info->arch = ARCH_X86;
                break;
            case EM_AARCH64:
                info->arch = ARCH_AARCH64;
                break;
            case EM_ARM:
                info->arch = ARCH_ARM;
                break;
            default:
                info->arch = ARCH_OTHER;
                break;
        }
        
        info->e_type = ehdr.e_type;
        info->e_machine = ehdr.e_machine;
        info->e_flags = ehdr.e_flags;
        info->entry_point = ehdr.e_entry;
        info->phdr_addr = ehdr.e_phoff;
        info->phdr_num = ehdr.e_phnum;
        info->phdr_size = ehdr.e_phentsize;
        info->shdr_addr = ehdr.e_shoff;
        info->shdr_num = ehdr.e_shnum;
        info->shdr_size = ehdr.e_shentsize;
        
        /* Look for PT_INTERP to determine static/dynamic */
        info->link_type = LINK_STATIC;
        
        if (ehdr.e_phoff != 0 && ehdr.e_phnum > 0) {
            lseek(fd, (off_t)ehdr.e_phoff, SEEK_SET);
            
            for (int i = 0; i < ehdr.e_phnum; i++) {
                Elf64_Phdr phdr;
                if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) {
                    break;
                }
                
                if (phdr.p_type == PT_INTERP) {
                    info->link_type = LINK_DYNAMIC;
                    
                    /* Read interpreter path */
                    if (phdr.p_filesz < sizeof(info->interp)) {
                        off_t cur = lseek(fd, 0, SEEK_CUR);
                        lseek(fd, (off_t)phdr.p_offset, SEEK_SET);
                        ssize_t n = read(fd, info->interp, phdr.p_filesz);
                        if (n > 0) {
                            info->interp[n] = '\0';
                        }
                        lseek(fd, cur, SEEK_SET);
                    }
                    break;
                }
            }
        }
        
        /*
         * Additional FreeBSD detection: check for .note.tag section
         * FreeBSD binaries often have EI_OSABI=0 but have FreeBSD notes
         */
        if (info->os_type != BINARY_FREEBSD && ehdr.e_shoff != 0) {
            /* Look for FreeBSD note */
            lseek(fd, (off_t)ehdr.e_shoff, SEEK_SET);
            
            for (int i = 0; i < ehdr.e_shnum; i++) {
                Elf64_Shdr shdr;
                if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr)) {
                    break;
                }
                
                if (shdr.sh_type == SHT_NOTE) {
                    /* Check note contents for FreeBSD marker */
                    off_t cur = lseek(fd, 0, SEEK_CUR);
                    lseek(fd, (off_t)shdr.sh_offset, SEEK_SET);
                    
                    char note[256];
                    ssize_t n = read(fd, note, sizeof(note) - 1);
                    if (n > 0) {
                        note[n] = '\0';
                        if (strstr(note, "FreeBSD") != NULL) {
                            info->os_type = BINARY_FREEBSD;
                        }
                    }
                    
                    lseek(fd, cur, SEEK_SET);
                }
            }
        }
    } else {
        /* 32-bit ELF - similar handling */
        Elf32_Ehdr ehdr;
        if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
            BSD_ERROR("Cannot read ELF header from %s", path);
            close(fd);
            return -1;
        }
        
        switch (ehdr.e_machine) {
            case EM_386:
                info->arch = ARCH_X86;
                break;
            case EM_ARM:
                info->arch = ARCH_ARM;
                break;
            default:
                info->arch = ARCH_OTHER;
                break;
        }
        
        info->e_type = ehdr.e_type;
        info->e_machine = ehdr.e_machine;
        info->e_flags = ehdr.e_flags;
        info->entry_point = ehdr.e_entry;
        info->phdr_addr = ehdr.e_phoff;
        info->phdr_num = ehdr.e_phnum;
        info->phdr_size = ehdr.e_phentsize;
        info->shdr_addr = ehdr.e_shoff;
        info->shdr_num = ehdr.e_shnum;
        info->shdr_size = ehdr.e_shentsize;
        
        info->link_type = LINK_STATIC;
        
        if (ehdr.e_phoff != 0 && ehdr.e_phnum > 0) {
            lseek(fd, (off_t)ehdr.e_phoff, SEEK_SET);
            
            for (int i = 0; i < ehdr.e_phnum; i++) {
                Elf32_Phdr phdr;
                if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) {
                    break;
                }
                
                if (phdr.p_type == PT_INTERP) {
                    info->link_type = LINK_DYNAMIC;
                    
                    if (phdr.p_filesz < sizeof(info->interp)) {
                        off_t cur = lseek(fd, 0, SEEK_CUR);
                        lseek(fd, (off_t)phdr.p_offset, SEEK_SET);
                        ssize_t n = read(fd, info->interp, phdr.p_filesz);
                        if (n > 0) {
                            info->interp[n] = '\0';
                        }
                        lseek(fd, cur, SEEK_SET);
                    }
                    break;
                }
            }
        }
    }
    
    close(fd);
    return 0;
}

void loader_print_info(const binary_info_t *info) {
    if (!info) return;
    
    printf("Binary: %s\n", info->path);
    printf("  OS/ABI:       %s\n", loader_os_name(info->os_type));
    printf("  Architecture: %s (%d-bit)\n", 
           loader_arch_name(info->arch),
           info->is_64bit ? 64 : 32);
    printf("  Link type:    %s\n", 
           info->link_type == LINK_STATIC ? "static" : "dynamic");
    printf("  Entry point:  0x%llx\n", (unsigned long long)info->entry_point);
    
    if (info->link_type == LINK_DYNAMIC && info->interp[0]) {
        printf("  Interpreter:  %s\n", info->interp);
    }
}

bool loader_is_compatible(const binary_info_t *info) {
    if (!info) return false;
    
    /* Only x86_64 FreeBSD binaries supported for now */
    if (info->arch != ARCH_X86_64) {
        return false;
    }
    
    /* FreeBSD binaries preferred, but allow Linux for testing */
    if (info->os_type != BINARY_FREEBSD && info->os_type != BINARY_LINUX) {
        return false;
    }
    
    return true;
}

const char *loader_os_name(binary_os_t os) {
    switch (os) {
        case BINARY_FREEBSD: return "FreeBSD";
        case BINARY_LINUX:   return "Linux";
        case BINARY_NETBSD:  return "NetBSD";
        case BINARY_OPENBSD: return "OpenBSD";
        case BINARY_OTHER:   return "Other";
        default:             return "Unknown";
    }
}

const char *loader_arch_name(binary_arch_t arch) {
    switch (arch) {
        case ARCH_X86:     return "x86 (i386)";
        case ARCH_X86_64:  return "x86_64 (amd64)";
        case ARCH_ARM:     return "ARM";
        case ARCH_AARCH64: return "AArch64 (ARM64)";
        case ARCH_OTHER:   return "Other";
        default:           return "Unknown";
    }
}

const char *loader_get_freebsd_interp(void) {
    return "/libexec/ld-elf.so.1";
}

int loader_prepare_env(const binary_info_t *info, char ***envp) {
    (void)info;
    (void)envp;
    
    /*
     * TODO: Set up environment for FreeBSD binary
     * - LD_LIBRARY_PATH for FreeBSD libs
     * - Any FreeBSD-specific env vars
     */
    return 0;
}
