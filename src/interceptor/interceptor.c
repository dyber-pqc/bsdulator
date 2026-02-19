/*
 * BSDulator - Syscall Interceptor Implementation
 * Uses ptrace to intercept and translate FreeBSD syscalls
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/ptrace.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include "bsdulator.h"
#include "runtime/freebsd_runtime.h"
#include "bsdulator/jail.h"

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 310
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 311
#endif

#define PTRACE_OPTIONS (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | \
                        PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | \
                        PTRACE_O_TRACEEXEC)

int interceptor_init(void) {
    BSD_TRACE("Initializing interceptor subsystem");
    return 0;
}

void interceptor_cleanup(void) {
    BSD_TRACE("Cleaning up interceptor subsystem");
}

/*
 * Inject a syscall into the child process and get the result.
 * This saves current state, executes one syscall, and restores state.
 * 
 * Note: We must handle syscall-stops due to PTRACE_O_TRACESYSGOOD.
 * Note: This doesn't work during exec event stops - use for normal stops only.
 */
__attribute__((unused))
static long inject_syscall(pid_t pid, long syscall_nr, 
                           long arg1, long arg2, long arg3,
                           long arg4, long arg5, long arg6) {
    struct user_regs_struct saved_regs, regs;
    
    /* Save current registers */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) < 0) {
        BSD_ERROR("inject_syscall: failed to save regs: %s", strerror(errno));
        return -1;
    }
    
    /* Get current RIP and read the instruction there */
    uint64_t rip = saved_regs.rip;
    
    /* Read the current bytes at RIP */
    errno = 0;
    long orig_code = ptrace(PTRACE_PEEKTEXT, pid, (void*)rip, NULL);
    if (errno != 0) {
        BSD_ERROR("inject_syscall: failed to read code at RIP: %s", strerror(errno));
        return -1;
    }
    
    /* Write syscall instruction (0x0f 0x05) followed by int3 (0xcc) */
    long syscall_code = (orig_code & ~0xFFFFFFUL) | 0xCC050FUL;  /* syscall; int3 */
    if (ptrace(PTRACE_POKETEXT, pid, (void*)rip, syscall_code) < 0) {
        BSD_ERROR("inject_syscall: failed to inject syscall: %s", strerror(errno));
        return -1;
    }
    
    /* Set up registers for the syscall */
    regs = saved_regs;
    regs.rax = syscall_nr;
    regs.rdi = arg1;
    regs.rsi = arg2;
    regs.rdx = arg3;
    regs.r10 = arg4;
    regs.r8 = arg5;
    regs.r9 = arg6;
    regs.rip = rip;
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("inject_syscall: failed to set regs: %s", strerror(errno));
        ptrace(PTRACE_POKETEXT, pid, (void*)rip, orig_code);
        return -1;
    }
    
    /* 
     * Continue and handle syscall-stops until we hit the int3 breakpoint.
     * Due to PTRACE_O_TRACESYSGOOD, we'll get stops at syscall entry/exit.
     */
    int status;
    int max_iterations = 10;  /* Safety limit */
    
    BSD_TRACE("inject_syscall: about to CONT, rip=0x%lx, syscall=%ld", rip, syscall_nr);
    
    while (max_iterations-- > 0) {
        BSD_TRACE("inject_syscall: calling PTRACE_CONT (iter %d)", 10 - max_iterations);
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
            BSD_ERROR("inject_syscall: cont failed: %s", strerror(errno));
            break;
        }
        
        BSD_TRACE("inject_syscall: waiting for stop...");
        waitpid(pid, &status, 0);
        BSD_TRACE("inject_syscall: got status=0x%x", status);
        
        if (!WIFSTOPPED(status)) {
            BSD_ERROR("inject_syscall: process not stopped: status=0x%x", status);
            break;
        }
        
        int sig = WSTOPSIG(status);
        BSD_TRACE("inject_syscall: signal=%d (0x%x)", sig, sig);
        
        /* Syscall stop (SIGTRAP | 0x80) - continue through it */
        if (sig == (SIGTRAP | 0x80)) {
            BSD_TRACE("inject_syscall: syscall stop, continuing");
            continue;
        }
        
        /* Regular SIGTRAP - this is our int3 breakpoint */
        if (sig == SIGTRAP) {
            BSD_TRACE("inject_syscall: got int3 breakpoint");
            break;
        }
        
        /* Other signal - unexpected */
        BSD_ERROR("inject_syscall: unexpected signal %d", sig);
        break;
    }
    
    /* Get the result */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("inject_syscall: failed to get result regs: %s", strerror(errno));
        ptrace(PTRACE_POKETEXT, pid, (void*)rip, orig_code);
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        return -1;
    }
    
    long result = regs.rax;
    BSD_TRACE("inject_syscall: syscall %ld returned %ld (0x%lx)", syscall_nr, result, result);
    
    /* Restore original code */
    if (ptrace(PTRACE_POKETEXT, pid, (void*)rip, orig_code) < 0) {
        BSD_ERROR("inject_syscall: failed to restore code: %s", strerror(errno));
    }
    
    /* Restore original registers */
    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) < 0) {
        BSD_ERROR("inject_syscall: failed to restore regs: %s", strerror(errno));
    }
    
    return result;
}

/*
 * Set up FreeBSD Thread Local Storage (TLS) for the child process.
 * 
 * FreeBSD TLS layout (Variant II, x86_64) from /usr/include/x86/tls.h:
 *   struct tcb {
 *       struct tcb *tcb_self;       // offset 0: self-reference (required by rtld)
 *       uintptr_t  *tcb_dtv;        // offset 8: DTV pointer (required by rtld)
 *       struct pthread *tcb_thread; // offset 16: pthread pointer
 *   };
 * 
 * libthr's _get_curthread() does: movq %fs:16, %rax
 * If tcb_thread is NULL, libthr panics with abort().
 * 
 * CRITICAL: Unlike what we initially thought, libthr expects tcb_thread
 * to point to a VALID pthread structure from the start. The FreeBSD kernel
 * sets this up before the program runs. If NULL, libthr enters error path
 * and aborts.
 * 
 * FreeBSD pthread structure (from thr_private.h):
 *   struct pthread {
 *       long tid;                   // offset 0: kernel thread ID
 *       struct umutex lock;         // offset 8: internal lock (~32 bytes)
 *       uint32_t cycle;             // offset 40
 *       int locklevel;              // offset 44
 *       int critical_count;         // offset 48
 *       int sigblock;               // offset 52
 *       uint32_t fsigblock;         // offset 56
 *       TAILQ_ENTRY tle;            // offset 64 (16 bytes)
 *       struct pthread *joiner;     // offset 80
 *       int state;                  // offset 88 (PS_RUNNING=0)
 *       ... more fields ...
 *   };
 */
/*
 * Probe if memory is writable via ptrace.
 * Returns 0 if accessible, -1 if not.
 */
static int probe_memory(pid_t pid, uint64_t addr) {
    errno = 0;
    long val = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
    if (errno != 0) {
        return -1;  /* Not readable */
    }
    /* Try to write back the same value */
    if (ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)val) < 0) {
        return -1;  /* Not writable */
    }
    return 0;
}

/*
 * Find a writable memory region for TLS.
 * 
 * CRITICAL: TLS must be FAR from RSP to avoid corruption!
 * The stack grows downward, and libthr uses significant stack space
 * during initialization. If TLS is within ~64KB of RSP, stack frames
 * will corrupt it.
 * 
 * FreeBSD kernel allocates TLS via mmap in a separate region.
 * We try to mimic this by using memory 1MB+ below RSP.
 */
static uint64_t find_tls_memory(pid_t pid, uint64_t rsp, size_t size __attribute__((unused))) {
    /*
     * Strategy 1: Use memory FAR below RSP (1MB, 2MB, 4MB).
     * Linux typically maps 8MB of stack initially, so 1-4MB below RSP
     * should be valid and far enough from active stack frames.
     */
    uint64_t far_offsets[] = {0x100000, 0x200000, 0x400000, 0x600000};  /* 1MB, 2MB, 4MB, 6MB */
    for (size_t i = 0; i < sizeof(far_offsets)/sizeof(far_offsets[0]); i++) {
        uint64_t addr = (rsp - far_offsets[i]) & ~0xFFFUL;
        BSD_TRACE("TLS: Trying RSP-0x%lx = 0x%lx", far_offsets[i], addr);
        if (probe_memory(pid, addr) == 0) {
            BSD_TRACE("TLS: Using stack area at 0x%lx (%.1f MB below RSP)", 
                      addr, (double)far_offsets[i] / (1024*1024));
            return addr;
        }
    }
    
    /*
     * Strategy 2: Read /proc/pid/maps and find the stack region.
     * Use an address near the BOTTOM of the stack mapping.
     */
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "[stack]")) {
                uint64_t start, end;
                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                    /* Use near the START of stack region (bottom of stack) */
                    uint64_t addr = (start + 0x10000) & ~0xFFFUL;  /* 64KB from bottom */
                    BSD_TRACE("TLS: Stack region 0x%lx-0x%lx, trying bottom 0x%lx",
                              start, end, addr);
                    fclose(f);
                    if (probe_memory(pid, addr) == 0) {
                        return addr;
                    }
                }
                break;
            }
        }
        fclose(f);
    }
    
    BSD_ERROR("TLS: Could not find writable memory for TLS");
    return 0;
}

/*
 * Inject mmap syscall to allocate TLS memory.
 * This is called after exec but before the binary runs.
 * Returns the allocated address, or 0 on failure.
 * 
 * NOTE: Currently disabled - doesn't work during exec event stops.
 * Kept for future use when we implement proper syscall injection.
 */
__attribute__((unused))
static uint64_t inject_mmap_for_tls(pid_t pid, size_t size) {
    struct user_regs_struct saved_regs, regs;
    
    /* Save current registers */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) < 0) {
        BSD_ERROR("inject_mmap: failed to save regs: %s", strerror(errno));
        return 0;
    }
    
    uint64_t rip = saved_regs.rip;
    
    /* Read original code at RIP */
    errno = 0;
    long orig_code = ptrace(PTRACE_PEEKTEXT, pid, (void*)rip, NULL);
    if (errno != 0) {
        BSD_ERROR("inject_mmap: failed to read code at RIP 0x%lx: %s", rip, strerror(errno));
        return 0;
    }
    
    /* Write syscall instruction (0x0f 0x05) followed by int3 (0xcc) */
    long syscall_code = (orig_code & ~0xFFFFFFUL) | 0xCC050FUL;  /* syscall; int3 */
    if (ptrace(PTRACE_POKETEXT, pid, (void*)rip, syscall_code) < 0) {
        BSD_ERROR("inject_mmap: failed to inject syscall: %s", strerror(errno));
        return 0;
    }
    
    /* Set up mmap syscall:
     * mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
     */
    regs = saved_regs;
    regs.rax = 9;           /* Linux mmap syscall */
    regs.rdi = 0;           /* addr = NULL */
    regs.rsi = size;        /* length */
    regs.rdx = 3;           /* PROT_READ | PROT_WRITE */
    regs.r10 = 0x22;        /* MAP_PRIVATE | MAP_ANONYMOUS */
    regs.r8 = (uint64_t)-1; /* fd = -1 */
    regs.r9 = 0;            /* offset = 0 */
    regs.rip = rip;         /* Execute at current RIP */
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("inject_mmap: failed to set regs: %s", strerror(errno));
        ptrace(PTRACE_POKETEXT, pid, (void*)rip, orig_code);
        return 0;
    }
    
    BSD_TRACE("inject_mmap: executing mmap(%zu bytes) at RIP=0x%lx", size, rip);
    
    /* Continue execution - will hit syscall then int3 */
    int status;
    int max_iter = 10;
    
    while (max_iter-- > 0) {
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
            BSD_ERROR("inject_mmap: CONT failed: %s", strerror(errno));
            break;
        }
        
        waitpid(pid, &status, 0);
        
        if (!WIFSTOPPED(status)) {
            BSD_ERROR("inject_mmap: process not stopped: status=0x%x", status);
            break;
        }
        
        int sig = WSTOPSIG(status);
        
        /* Syscall stop (SIGTRAP | 0x80) - continue through it */
        if (sig == (SIGTRAP | 0x80)) {
            BSD_TRACE("inject_mmap: syscall stop, continuing");
            continue;
        }
        
        /* Regular SIGTRAP - this is our int3 breakpoint */
        if (sig == SIGTRAP) {
            BSD_TRACE("inject_mmap: hit int3 breakpoint");
            break;
        }
        
        BSD_ERROR("inject_mmap: unexpected signal %d", sig);
        break;
    }
    
    /* Get the result */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("inject_mmap: failed to get result: %s", strerror(errno));
        ptrace(PTRACE_POKETEXT, pid, (void*)rip, orig_code);
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        return 0;
    }
    
    uint64_t result = regs.rax;
    
    /* Restore original code */
    if (ptrace(PTRACE_POKETEXT, pid, (void*)rip, orig_code) < 0) {
        BSD_ERROR("inject_mmap: failed to restore code: %s", strerror(errno));
    }
    
    /* Restore original registers */
    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) < 0) {
        BSD_ERROR("inject_mmap: failed to restore regs: %s", strerror(errno));
    }
    
    /* Check for error (mmap returns -errno on failure) */
    if (result > 0xfffffffffffff000UL) {
        BSD_ERROR("inject_mmap: mmap failed with error %ld", -(long)result);
        return 0;
    }
    
    BSD_TRACE("inject_mmap: allocated %zu bytes at 0x%lx", size, result);
    return result;
}

/*
 * Set up FreeBSD TLS for a process.
 * 
 * @param pid Process ID
 * @param skip_globals If true, skip writing to hardcoded global addresses
 *                     (used for jailed processes where addresses differ)
 */
static int setup_freebsd_tls_ex(pid_t pid, int skip_globals) {
    BSD_TRACE("Setting up FreeBSD TLS for PID %d (skip_globals=%d)", pid, skip_globals);
    
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("Failed to get registers: %s", strerror(errno));
        return -1;
    }
    
    /*
     * Memory layout for TLS (128KB total - FreeBSD Variant II):
     * 
     * The ELF TLS segment requires 0x1ABC0 (109KB) of space!
     * In Variant II, TLS data is at NEGATIVE offsets from TCB (%fs).
     * 
     * Layout:
     *   tls_base + 0x00000: Start of TLS data region (zeroed)
     *   tls_base + 0x1E000: TCB (Thread Control Block)  <- %fs points here
     *   tls_base + 0x1E040: DTV  
     *   tls_base + 0x1E100: pthread structure
     * 
     * This gives ~120KB below TCB for TLS data, which is > 109KB needed.
     * 
     * CRITICAL: We MUST allocate enough space for the full TLS segment!
     * libthr accesses TLS data at offsets like TCB-0x1A878.
     */
    
    uint64_t tls_size = 0x20000;  /* 128KB for TLS structures */
    
    /* Try to allocate TLS via mmap injection first */
    uint64_t tls_base = 0; // inject_mmap_for_tls(pid, tls_size);
    
    if (tls_base == 0) {
        /* mmap injection failed - fall back to stack-based TLS */
        BSD_WARN("mmap injection failed, falling back to stack-based TLS");
        tls_base = find_tls_memory(pid, regs.rsp, tls_size);
        
        if (tls_base == 0) {
            BSD_ERROR("Cannot allocate TLS memory");
            return -1;
        }
    }
    
    /* TLS structures - TCB at HIGH end to provide space for TLS data below */
    uint64_t tcb_ptr = tls_base + 0x1E000;         /* TCB at +120KB */
    uint64_t dtv_ptr = tcb_ptr + 0x40;             /* DTV after TCB */
    uint64_t pthread_ptr = tcb_ptr + 0x100;        /* pthread struct at TCB+256 */
    
    BSD_TRACE("TLS: base=0x%lx, DTV=0x%lx, TCB=0x%lx, pthread=0x%lx", 
              tls_base, dtv_ptr, tcb_ptr, pthread_ptr);
    
    /*
     * Initialize TCB and DTV to match FreeBSD kernel's layout.
     * 
     * TCB layout:
     *   TCB[0] = self pointer (points to TCB itself)
     *   TCB[1] = DTV pointer
     *   TCB[2] = pthread pointer (MUST be valid, not NULL!)
     * 
     * DTV layout:
     *   DTV[0] = 1 (generation counter)
     *   DTV[1] = 1 (module count) 
     *   DTV[2] = pointer to TLS data (at tls_base for Variant II)
     * 
     * CRITICAL: libthr checks global _thr_initial (at 0x15072c8) during
     * initialization. If NULL, it aborts! We must set both TCB[2] and
     * the global to point to a valid pthread structure.
     */
    
    /*
     * CRITICAL: FreeBSD TLS Variant II layout
     * TLS data is at NEGATIVE offsets from TCB: TCB - tls_memsz
     * 
     * From ELF PT_TLS segment (rescue/echo):
     *   File size (.tdata): 0xa60 = 2656 bytes (initialized data)
     *   Mem size (.tdata+.tbss): 0x1abc0 = 109504 bytes (total TLS)
     *   File offset: 0x12b8d80
     * 
     * TLS block location: TCB - 0x1ABC0
     */
    uint64_t tls_memsz = 0x1ABC0;      /* Total TLS memory size */
    uint64_t tls_filesz = 0xA60;       /* .tdata size (initialized) */  
    uint64_t tls_fileoff = 0x12b8d80;  /* .tdata file offset in ELF */
    
    /* TLS block is at TCB - memsz (Variant II) */
    uint64_t tls_block = tcb_ptr - tls_memsz;
    uint64_t tls_data_ptr = tls_block;  /* DTV[2] points here */
    
    BSD_TRACE("TLS block: 0x%lx (TCB=0x%lx - 0x%lx), filesz=0x%lx", 
              tls_block, tcb_ptr, tls_memsz, tls_filesz);
    
    /* First, zero the entire TLS region */
    size_t tls_data_size = tcb_ptr - tls_base;
    uint8_t *zero_buf = calloc(1, tls_data_size);
    if (zero_buf) {
        struct iovec local_iov = { zero_buf, tls_data_size };
        struct iovec remote_iov = { (void*)tls_base, tls_data_size };
        ssize_t written = syscall(SYS_process_vm_writev, pid, &local_iov, 1, &remote_iov, 1, 0);
        if (written < 0) {
            BSD_WARN("Failed to zero TLS region: %s", strerror(errno));
        } else {
            BSD_TRACE("Zeroed %zd bytes of TLS region", written);
        }
        free(zero_buf);
    }
    
    /* Now copy .tdata from the ELF binary */
    char exe_path[256];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    FILE *elf_file = fopen(exe_path, "rb");
    if (elf_file) {
        uint8_t *tdata_buf = malloc(tls_filesz);
        if (tdata_buf) {
            if (fseek(elf_file, tls_fileoff, SEEK_SET) == 0 &&
                fread(tdata_buf, 1, tls_filesz, elf_file) == tls_filesz) {
                
                struct iovec local_iov = { tdata_buf, tls_filesz };
                struct iovec remote_iov = { (void*)tls_block, tls_filesz };
                ssize_t written = syscall(SYS_process_vm_writev, pid, 
                                          &local_iov, 1, &remote_iov, 1, 0);
                if (written > 0) {
                    BSD_TRACE("Copied %zd bytes of .tdata to TLS block at 0x%lx", written, tls_block);
                } else {
                    BSD_WARN("Failed to copy .tdata: %s", strerror(errno));
                }
            } else {
                BSD_WARN("Failed to read .tdata from ELF at offset 0x%lx", tls_fileoff);
            }
            free(tdata_buf);
        }
        fclose(elf_file);
    } else {
        BSD_WARN("Could not open %s to read .tdata", exe_path);
    }

    /* Initialize DTV to match FreeBSD exactly */
    ptrace(PTRACE_POKEDATA, pid, (void*)(dtv_ptr + 0), (void*)1UL);         /* gen = 1 */
    ptrace(PTRACE_POKEDATA, pid, (void*)(dtv_ptr + 8), (void*)1UL);         /* count = 1 */
    ptrace(PTRACE_POKEDATA, pid, (void*)(dtv_ptr + 16), (void*)tls_data_ptr); /* TLS data ptr */
    ptrace(PTRACE_POKEDATA, pid, (void*)(dtv_ptr + 24), (void*)0UL);        /* padding */
    
    BSD_TRACE("DTV: gen=1 count=1 tls_data=0x%lx", tls_data_ptr);
    
    /*
     * Initialize minimal pthread structure.
     * libthr checks _thr_initial global (at 0x15072c8) and aborts if NULL.
     * We must provide a valid pthread with at minimum:
     *   - offset 0: tid (thread ID)
     *   - other fields zeroed
     */
    for (int i = 0; i < 0x200; i += 8) {  /* Zero 512 bytes for pthread */
        ptrace(PTRACE_POKEDATA, pid, (void*)(pthread_ptr + i), (void*)0UL);
    }
    /* Set tid at offset 0 */
    ptrace(PTRACE_POKEDATA, pid, (void*)(pthread_ptr + 0), (void*)(long)pid);
    BSD_TRACE("pthread: ptr=0x%lx, tid=%d", pthread_ptr, pid);
    
    /* Initialize TCB */
    if (ptrace(PTRACE_POKEDATA, pid, (void*)(tcb_ptr + 0), (void*)tcb_ptr) < 0) {
        BSD_ERROR("Failed to write tcb_self: %s", strerror(errno));
        return -1;
    }
    if (ptrace(PTRACE_POKEDATA, pid, (void*)(tcb_ptr + 8), (void*)dtv_ptr) < 0) {
        BSD_ERROR("Failed to write tcb_dtv: %s", strerror(errno));
        return -1;
    }
    /* TCB[2] = pthread pointer - libthr's _get_curthread() reads this */
    if (ptrace(PTRACE_POKEDATA, pid, (void*)(tcb_ptr + 16), (void*)pthread_ptr) < 0) {
        BSD_ERROR("Failed to write tcb_thread: %s", strerror(errno));
        return -1;
    }
    ptrace(PTRACE_POKEDATA, pid, (void*)(tcb_ptr + 24), (void*)0UL);         /* spare */
    
    /*
     * CRITICAL: Set _thr_initial global at 0x15072c8.
     * libthr checks this global and aborts if NULL!
     * Found via objdump: address 0x74d1f4 does "test %rdi,%rdi; jne; call abort"
     * where RDI is loaded from 0x15072c8.
     */
    /*
     * Write to hardcoded global addresses only for non-jailed processes.
     * These addresses are specific to the rescue binaries' memory layout
     * and won't exist in jailed processes running different binaries.
     */
#define FREEBSD_THR_INITIAL_ADDR 0x15072c8
#define FREEBSD_THR_REFCOUNT_ADDR 0x15072c0
#define FREEBSD_STACK_CHK_GUARD_ADDR 0x180b5a0
    if (!skip_globals) {
        if (ptrace(PTRACE_POKEDATA, pid, (void*)FREEBSD_THR_INITIAL_ADDR, (void*)pthread_ptr) < 0) {
            BSD_WARN("Failed to write _thr_initial at 0x%lx: %s", 
                     (unsigned long)FREEBSD_THR_INITIAL_ADDR, strerror(errno));
            /* Don't fail - memory might not be mapped yet */
        } else {
            BSD_TRACE("_thr_initial at 0x%lx = 0x%lx", 
                      (unsigned long)FREEBSD_THR_INITIAL_ADDR, pthread_ptr);
        }
        
        /*
         * CRITICAL: Initialize thread reference counter at 0x15072c0.
         * libthr checks this counter and aborts if zero!
         * Found via objdump: address 0x75a6e4 does "cmpq $0x0,0x15072c0; je abort"
         * This counter is incremented/decremented during thread creation/destruction.
         */
        if (ptrace(PTRACE_POKEDATA, pid, (void*)FREEBSD_THR_REFCOUNT_ADDR, (void*)1UL) < 0) {
            BSD_WARN("Failed to write thread refcount at 0x%lx: %s", 
                     (unsigned long)FREEBSD_THR_REFCOUNT_ADDR, strerror(errno));
        } else {
            BSD_TRACE("Thread refcount at 0x%lx = 1", 
                      (unsigned long)FREEBSD_THR_REFCOUNT_ADDR);
        }
        
        /*
         * CRITICAL: Initialize __stack_chk_guard at 0x180b5a0.
         * This is the stack canary value used for stack smashing protection.
         * FreeBSD startup code should read AT_CANARY from auxv and copy it here,
         * but since we're setting up the environment, we must initialize it directly.
         * The value must match what we put in AT_CANARY (from g_freebsd_runtime.canary).
         */
        uint64_t canary_value;
        memcpy(&canary_value, g_freebsd_runtime.canary, sizeof(canary_value));
        if (ptrace(PTRACE_POKEDATA, pid, (void*)FREEBSD_STACK_CHK_GUARD_ADDR, (void*)canary_value) < 0) {
            BSD_WARN("Failed to write __stack_chk_guard at 0x%lx: %s", 
                     (unsigned long)FREEBSD_STACK_CHK_GUARD_ADDR, strerror(errno));
        } else {
            BSD_TRACE("__stack_chk_guard at 0x%lx = 0x%lx", 
                      (unsigned long)FREEBSD_STACK_CHK_GUARD_ADDR, canary_value);
            
            /* Verify the write */
            errno = 0;
            uint64_t readback = ptrace(PTRACE_PEEKDATA, pid, (void*)FREEBSD_STACK_CHK_GUARD_ADDR, NULL);
            if (errno == 0) {
                if (readback != canary_value) {
                    BSD_ERROR("CANARY MISMATCH at __stack_chk_guard! wrote=0x%lx read=0x%lx",
                              canary_value, readback);
                } else {
                    BSD_TRACE("__stack_chk_guard verified");
                }
            }
        }
    } else {
        BSD_TRACE("Skipping hardcoded global writes for jailed process");
    }
    
    /* 
     * Set FS base to point to TCB AND update RSP to reserve TLS space.
     * Re-read registers and set both fs_base and rsp.
     */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("Failed to re-read registers: %s", strerror(errno));
        return -1;
    }
    
    BSD_TRACE("Current fs_base=0x%llx, rsp=0x%llx", 
              (unsigned long long)regs.fs_base, (unsigned long long)regs.rsp);
    BSD_TRACE("Setting fs_base=0x%lx", tcb_ptr);
    
    regs.fs_base = tcb_ptr;
    /* TLS is placed in a probed writable region - RSP unchanged */
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("Failed to set fs_base via SETREGS: %s", strerror(errno));
        return -1;
    }
    
    /* Verify setup - CRITICAL: check that FS was actually set */
    struct user_regs_struct verify_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &verify_regs) == 0) {
        BSD_TRACE("TLS setup complete: FS=0x%lx (expected 0x%lx)", 
                  (unsigned long)verify_regs.fs_base, tcb_ptr);
        
        if (verify_regs.fs_base != tcb_ptr) {
            BSD_ERROR("FS_BASE mismatch! Got 0x%lx, expected 0x%lx",
                      (unsigned long)verify_regs.fs_base, tcb_ptr);
            return -1;
        }
        
        /* Read back and verify TCB */
        errno = 0;
        uint64_t v0 = ptrace(PTRACE_PEEKDATA, pid, (void*)(tcb_ptr + 0), NULL);
        if (errno) {
            BSD_ERROR("Failed to read tcb_self at 0x%lx: %s", tcb_ptr, strerror(errno));
            return -1;
        }
        errno = 0;
        uint64_t v8 = ptrace(PTRACE_PEEKDATA, pid, (void*)(tcb_ptr + 8), NULL);
        uint64_t v16 = ptrace(PTRACE_PEEKDATA, pid, (void*)(tcb_ptr + 16), NULL);
        BSD_TRACE("TCB verify: self=0x%lx dtv=0x%lx pthread=0x%lx", v0, v8, v16);
        
        /* Verify TCB values are correct */
        if (v0 != tcb_ptr || v8 != dtv_ptr || v16 != pthread_ptr) {
            BSD_ERROR("TCB data mismatch! self=0x%lx (expected 0x%lx), dtv=0x%lx (expected 0x%lx), pthread=0x%lx (expected 0x%lx)",
                      v0, tcb_ptr, v8, dtv_ptr, v16, pthread_ptr);
            return -1;
        }
    } else {
        BSD_ERROR("Failed to verify TLS setup: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

/* Wrapper for backwards compatibility */
static int setup_freebsd_tls(pid_t pid) {
    return setup_freebsd_tls_ex(pid, 0);  /* Don't skip globals */
}

/*
 * Fix up registers for FreeBSD binary startup.
 * FreeBSD expects %rdi to point to argc on stack.
 * 
 * FreeBSD ABI requires 16-byte stack alignment at function entry.
 * The stack layout at _start should be:
 *   RSP -> argc (8 bytes)
 *          argv[0]
 *          argv[1]
 *          ...
 *          NULL
 *          envp[0]
 *          ...
 *          NULL
 *          auxv
 *          ...
 * 
 * The key difference is that FreeBSD may expect RSP to be
 * aligned differently than Linux provides after exec.
 */
static int fixup_freebsd_entry(pid_t pid) {
    struct user_regs_struct regs;
    
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("Failed to get registers for fixup: %s", strerror(errno));
        return -1;
    }
    
    BSD_TRACE("Before fixup: RDI=0x%llx RSI=0x%llx RSP=0x%llx RIP=0x%llx",
              (unsigned long long)regs.rdi,
              (unsigned long long)regs.rsi,
              (unsigned long long)regs.rsp,
              (unsigned long long)regs.rip);
    
    BSD_TRACE("RSP alignment: RSP %% 16 = %llu", 
              (unsigned long long)(regs.rsp % 16));
    
    /*
     * FreeBSD ABI stack alignment:
     * FreeBSD expects RSP = 16n+8 at _start, Linux provides RSP = 16n.
     * We need to shift the entire stack data down by 8 bytes.
     * 
     * Important: Read all data first, then write, to avoid overlap corruption.
     */  
    uint64_t argc_location = regs.rsp;  /* Save original RSP - this is where argc lives */
    
    if (regs.rsp % 16 == 0) {
        uint64_t new_rsp = regs.rsp - 8;
        /* Write a zero as padding at the new RSP location */
        if (ptrace(PTRACE_POKEDATA, pid, (void*)new_rsp, 0) < 0) {
            BSD_WARN("Failed to write stack padding: %s", strerror(errno));
        } else {
            regs.rsp = new_rsp;
            BSD_TRACE("Stack realigned: RSP adjusted by -8 to 0x%llx",
                      (unsigned long long)new_rsp);
        }
    }

    /* RDI = pointer to argc (original RSP, where stack data lives) */
    regs.rdi = argc_location;
    regs.rsi = 0;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("Failed to set registers for fixup: %s", strerror(errno));
        return -1;
    }
    
    BSD_TRACE("After fixup: RDI=0x%llx RSI=0x%llx RSP=0x%llx (alignment: %llu)",
              (unsigned long long)regs.rdi,
              (unsigned long long)regs.rsi,
              (unsigned long long)regs.rsp,
              (unsigned long long)(regs.rsp % 16));
    
    return 0;
}

pid_t interceptor_spawn(const char *binary, char *const argv[], char *const envp[]) {
    BSD_TRACE("Spawning process: %s", binary);
    
    pid_t pid = fork();
    
    if (pid < 0) {
        BSD_ERROR("fork() failed: %s", strerror(errno));
        return -1;
    }
    
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace(TRACEME)");
            _exit(127);
        }
        raise(SIGSTOP);
        execve(binary, argv, envp);
        perror("execve");
        _exit(127);
    }
    
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        BSD_ERROR("waitpid() failed: %s", strerror(errno));
        kill(pid, SIGKILL);
        return -1;
    }
    
    if (!WIFSTOPPED(status)) {
        BSD_ERROR("Child did not stop as expected (status=0x%x)", status);
        kill(pid, SIGKILL);
        return -1;
    }
    
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_OPTIONS) < 0) {
        BSD_ERROR("ptrace(SETOPTIONS) failed: %s", strerror(errno));
        kill(pid, SIGKILL);
        return -1;
    }
    
    BSD_TRACE("Process spawned and ready, PID=%d", (int)pid);
    return pid;
}

int interceptor_attach(pid_t pid) {
    BSD_TRACE("Attaching to process %d", (int)pid);
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        BSD_ERROR("ptrace(ATTACH) failed: %s", strerror(errno));
        return -1;
    }
    
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        BSD_ERROR("waitpid() failed: %s", strerror(errno));
        return -1;
    }
    
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_OPTIONS) < 0) {
        BSD_ERROR("ptrace(SETOPTIONS) failed: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

int interceptor_detach(pid_t pid) {
    BSD_TRACE("Detaching from process %d", (int)pid);
    
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        BSD_ERROR("ptrace(DETACH) failed: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

int interceptor_get_regs(pid_t pid, regs_t *regs) {
    struct user_regs_struct uregs;
    
    if (ptrace(PTRACE_GETREGS, pid, NULL, &uregs) < 0) {
        BSD_ERROR("ptrace(GETREGS) failed: %s", strerror(errno));
        return -1;
    }
    
    regs->rax = uregs.rax;
    regs->rbx = uregs.rbx;
    regs->rcx = uregs.rcx;
    regs->rdx = uregs.rdx;
    regs->rsi = uregs.rsi;
    regs->rdi = uregs.rdi;
    regs->rbp = uregs.rbp;
    regs->rsp = uregs.rsp;
    regs->r8 = uregs.r8;
    regs->r9 = uregs.r9;
    regs->r10 = uregs.r10;
    regs->r11 = uregs.r11;
    regs->r12 = uregs.r12;
    regs->r13 = uregs.r13;
    regs->r14 = uregs.r14;
    regs->r15 = uregs.r15;
    regs->rip = uregs.rip;
    regs->orig_rax = uregs.orig_rax;
    regs->eflags = uregs.eflags;
    
    return 0;
}

int interceptor_set_regs(pid_t pid, const regs_t *regs) {
    struct user_regs_struct uregs;
    
    if (ptrace(PTRACE_GETREGS, pid, NULL, &uregs) < 0) {
        return -1;
    }
    
    uregs.rax = regs->rax;
    uregs.rbx = regs->rbx;
    uregs.rcx = regs->rcx;
    uregs.rdx = regs->rdx;
    uregs.rsi = regs->rsi;
    uregs.rdi = regs->rdi;
    uregs.rbp = regs->rbp;
    uregs.rsp = regs->rsp;
    uregs.r8 = regs->r8;
    uregs.r9 = regs->r9;
    uregs.r10 = regs->r10;
    uregs.r11 = regs->r11;
    uregs.r12 = regs->r12;
    uregs.r13 = regs->r13;
    uregs.r14 = regs->r14;
    uregs.r15 = regs->r15;
    uregs.rip = regs->rip;
    uregs.orig_rax = regs->orig_rax;
    uregs.eflags = regs->eflags;
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &uregs) < 0) {
        BSD_ERROR("ptrace(SETREGS) failed: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

int interceptor_set_syscall(pid_t pid, uint64_t syscall_nr) {
    struct user_regs_struct regs;
    
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        return -1;
    }
    
    /* Set orig_rax to change the syscall that will execute */
    regs.orig_rax = syscall_nr;
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        return -1;
    }
    
    return 0;
}

int interceptor_set_args(pid_t pid, uint64_t args[6]) {
    struct user_regs_struct regs;
    
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        return -1;
    }
    
    regs.rdi = args[0];
    regs.rsi = args[1];
    regs.rdx = args[2];
    regs.r10 = args[3];
    regs.r8 = args[4];
    regs.r9 = args[5];
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        return -1;
    }
    
    return 0;
}

int interceptor_set_return(pid_t pid, int64_t retval) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        return -1;
    }
    /*
     * FreeBSD syscall error convention:
     * - Success: rax = return value, carry flag (CF) = 0
     * - Error: rax = positive errno, carry flag (CF) = 1
     */
    if (retval < 0 && retval > -4096) {
        /* This is an error - set CF and use positive errno */
        regs.rax = (uint64_t)abi_translate_errno(-retval);
        regs.eflags |= 0x1;              /* Set carry flag (CF) */
    } else {
        /* Success - clear CF */
        regs.rax = (uint64_t)retval;
        regs.eflags &= ~0x1;             /* Clear carry flag */
    }
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        return -1;
    }
    return 0;
}

int interceptor_skip_syscall(pid_t pid, int64_t retval) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        return -1;
    }
    regs.orig_rax = (uint64_t)-1;
    
    /*
     * FreeBSD syscall error convention:
     * - Success: rax = return value, carry flag (CF) = 0
     * - Error: rax = positive errno, carry flag (CF) = 1
     * 
     * Linux convention uses negative errno in rax.
     * We need to translate for FreeBSD binaries.
     */
    if (retval < 0 && retval > -4096) {
        /* This is an error - set CF and use positive errno */
        regs.rax = (uint64_t)abi_translate_errno(-retval);  /* Positive errno */
        regs.eflags |= 0x1;              /* Set carry flag (CF) */
    } else {
        /* Success - clear CF */
        regs.rax = (uint64_t)retval;
        regs.eflags &= ~0x1;             /* Clear carry flag */
    }
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        return -1;
    }
    return 0;
}

ssize_t interceptor_read_mem(pid_t pid, void *local, const void *remote, size_t len) {
    struct iovec local_iov = { local, len };
    struct iovec remote_iov = { (void *)remote, len };
    
    ssize_t result = syscall(SYS_process_vm_readv, pid, &local_iov, 1, &remote_iov, 1, 0);
    if (result < 0) {
        if (len <= sizeof(long)) {
            errno = 0;
            long data = ptrace(PTRACE_PEEKDATA, pid, remote, NULL);
            if (errno != 0) {
                return -1;
            }
            memcpy(local, &data, len);
            return (ssize_t)len;
        }
        return -1;
    }
    
    return result;
}

ssize_t interceptor_write_mem(pid_t pid, const void *local, void *remote, size_t len) {
    struct iovec local_iov = { (void *)local, len };
    struct iovec remote_iov = { remote, len };
    
    ssize_t result = syscall(SYS_process_vm_writev, pid, &local_iov, 1, &remote_iov, 1, 0);
    if (result < 0) {
        if (len <= sizeof(long)) {
            long data = 0;
            memcpy(&data, local, len);
            if (ptrace(PTRACE_POKEDATA, pid, remote, data) < 0) {
                return -1;
            }
            return (ssize_t)len;
        }
        return -1;
    }
    
    return result;
}

ssize_t interceptor_read_string(pid_t pid, char *local, const void *remote, size_t maxlen) {
    size_t i;
    
    for (i = 0; i < maxlen - 1; i += sizeof(long)) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, pid, (char *)remote + i, NULL);
        if (errno != 0) {
            if (i == 0) return -1;
            break;
        }
        
        size_t remaining = maxlen - 1 - i;
        size_t to_copy = remaining < sizeof(long) ? remaining : sizeof(long);
        memcpy(local + i, &data, to_copy);
        
        for (size_t j = 0; j < to_copy; j++) {
            if (local[i + j] == '\0') {
                return (ssize_t)(i + j);
            }
        }
    }
    local[maxlen - 1] = '\0';
    return (ssize_t)(maxlen - 1);
}

/*
 * Fix argv[0] after exec to contain the translated path.
 * This is critical for multi-call binaries like /rescue/ which use
 * argv[0] or AT_EXECPATH to determine which program to run.
 */
static int fix_argv0_after_exec(pid_t pid) {
    const char *freebsd_root = bsdulator_get_freebsd_root();
    if (!freebsd_root || freebsd_root[0] == '\0') {
        return -1;
    }
    
    /*
     * CRITICAL: Skip argv[0] translation for processes inside a jail!
     * After jail_attach + chroot, the process is already inside the jail's
     * root filesystem. Translating argv[0] would create an invalid path.
     */
    int jid = jail_get_process_jid(pid);
    if (jid > 0) {
        BSD_TRACE("fix_argv0: skipping for jailed process (jid=%d)", jid);
        return 0;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("fix_argv0: Failed to get regs");
        return -1;
    }

    /* Stack layout after exec: [argc] [argv[0]] [argv[1]] ... [NULL] [envp...] */
    uint64_t rsp = regs.rsp;
    uint64_t argc_ptr = (rsp % 16 == 8) ? rsp + 8 : rsp;
    
    /* Read argc */
    long argc = ptrace(PTRACE_PEEKDATA, pid, (void *)argc_ptr, NULL);
    if (argc <= 0) {
        BSD_WARN("fix_argv0: Invalid argc=%ld", argc);
        return -1;
    }

    /* Read argv[0] pointer (at rsp + 8) */
    uint64_t argv0_ptr_addr = argc_ptr + 8;
    uint64_t argv0_ptr = ptrace(PTRACE_PEEKDATA, pid, (void *)argv0_ptr_addr, NULL);
    if (argv0_ptr == 0) {
        BSD_WARN("fix_argv0: NULL argv[0] pointer");
        return -1;
    }

    /* Read argv[0] string */
    char argv0_buf[1024];
    ssize_t len = interceptor_read_string(pid, argv0_buf, (const void *)argv0_ptr, sizeof(argv0_buf));
    if (len <= 0) {
        BSD_WARN("fix_argv0: Failed to read argv[0] string");
        return -1;
    }

    BSD_TRACE("fix_argv0: Current argv[0] = '%s'", argv0_buf);

    /* Only translate absolute paths */
    if (argv0_buf[0] != '/') {
        return 0;  /* Not an absolute path, nothing to do */
    }

    /* Check if it's a path we should translate */
    int should_translate = 0;
    if (strncmp(argv0_buf, "/libexec/", 9) == 0 ||
        strncmp(argv0_buf, "/lib/", 5) == 0 ||
        strncmp(argv0_buf, "/usr/lib/", 9) == 0 ||
        strncmp(argv0_buf, "/usr/libexec/", 13) == 0 ||
        strncmp(argv0_buf, "/bin/", 5) == 0 ||
        strncmp(argv0_buf, "/sbin/", 6) == 0 ||
        strncmp(argv0_buf, "/usr/bin/", 9) == 0 ||
        strncmp(argv0_buf, "/usr/sbin/", 10) == 0 ||
        strncmp(argv0_buf, "/rescue/", 8) == 0) {
        should_translate = 1;
    }

    if (!should_translate) {
        return 0;  /* Not a FreeBSD system path */
    }

    /* Build the translated path */
    char new_argv0[2048];
    size_t root_len = strlen(freebsd_root);
    if (root_len > 0 && freebsd_root[root_len - 1] == '/') {
        root_len--;
    }
    snprintf(new_argv0, sizeof(new_argv0), "%.*s%s", (int)root_len, freebsd_root, argv0_buf);

    BSD_INFO("fix_argv0: Translating '%s' -> '%s'", argv0_buf, new_argv0);

    /* Write new argv[0] string to a safe location on the stack */
    size_t new_len = strlen(new_argv0) + 1;
    uint64_t new_str_addr = (rsp - new_len - 256) & ~0xFULL;  /* Align to 16 bytes */

    ssize_t written = interceptor_write_mem(pid, new_argv0, (void *)new_str_addr, new_len);
    if (written < 0) {
        BSD_ERROR("fix_argv0: Failed to write new argv[0] string");
        return -1;
    }

    /* Update argv[0] pointer to point to new string */
    if (ptrace(PTRACE_POKEDATA, pid, (void *)argv0_ptr_addr, (void *)new_str_addr) < 0) {
        BSD_ERROR("fix_argv0: Failed to update argv[0] pointer");
        return -1;
    }

    BSD_INFO("fix_argv0: Successfully updated argv[0] to '%s' @ 0x%lx", new_argv0, new_str_addr);
    return 0;
}
    

/*
 * Rewrite execve for jailed processes to use the FreeBSD dynamic linker.
 * 
 * After chroot, when a jailed process tries to exec a FreeBSD binary like
 * /bin/sh, the Linux kernel can't find the FreeBSD interpreter at
 * /libexec/ld-elf.so.1 because it looks at the HOST filesystem, not the
 * chrooted one. The solution is to rewrite:
 *   execve("/bin/sh", argv, envp)
 * to:
 *   execve("/libexec/ld-elf.so.1", ["/libexec/ld-elf.so.1", "/bin/sh", ...], envp)
 * 
 * This way the kernel can find ld-elf.so.1 in the chroot and it will load /bin/sh.
 * 
 * Returns 1 if execve was rewritten, 0 if no rewrite needed, -1 on error.
 */
static int rewrite_jailed_execve(pid_t pid, uint64_t *args) {
    int jid = jail_get_process_jid(pid);
    if (jid <= 0) {
        return 0;  /* Not jailed, no rewrite needed */
    }
    
    /* Read the path being exec'd */
    char path_buf[1024];
    ssize_t path_len = interceptor_read_string(pid, path_buf, (const void *)args[0], sizeof(path_buf));
    if (path_len <= 0) {
        BSD_WARN("rewrite_jailed_execve: failed to read path");
        return -1;
    }
    
    BSD_INFO("rewrite_jailed_execve: jailed process (jid=%d) exec'ing '%s'", jid, path_buf);
    
    /* Skip if already executing ld-elf.so.1 */
    if (strstr(path_buf, "ld-elf.so") != NULL) {
        BSD_TRACE("rewrite_jailed_execve: already ld-elf, skipping");
        return 0;
    }
    
    /* Skip /rescue/ binaries - they are statically linked and don't need ld-elf */
    if (strncmp(path_buf, "/rescue/", 8) == 0) {
        BSD_TRACE("rewrite_jailed_execve: /rescue/ binary is static, skipping");
        return 0;
    }
    
    /* Get registers to find stack space */
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("rewrite_jailed_execve: failed to get regs");
        return -1;
    }
    
    /* We need to:
     * 1. Write "/libexec/ld-elf.so.1" to child's stack
     * 2. Build new argv array: [ld-elf, original_path, original_argv[1:], NULL]
     * 3. Update args[0] to point to ld-elf path
     * 4. Update args[1] to point to new argv array
     */
    
    const char *ldelf = "/libexec/ld-elf.so.1";
    size_t ldelf_len = strlen(ldelf) + 1;
    
    /* Allocate stack space for new strings and argv */
    uint64_t stack_top = (regs.rsp - 4096) & ~0xFULL;  /* Leave lots of room */
    uint64_t ldelf_addr = stack_top;
    uint64_t orig_path_addr = ldelf_addr + ldelf_len;
    uint64_t new_argv_addr = (orig_path_addr + path_len + 1 + 15) & ~0x7ULL;  /* Align for pointers */
    
    /* Write ld-elf path */
    if (interceptor_write_mem(pid, ldelf, (void *)ldelf_addr, ldelf_len) < 0) {
        BSD_ERROR("rewrite_jailed_execve: failed to write ldelf path");
        return -1;
    }
    
    /* Write original path */
    if (interceptor_write_mem(pid, path_buf, (void *)orig_path_addr, path_len + 1) < 0) {
        BSD_ERROR("rewrite_jailed_execve: failed to write orig path");
        return -1;
    }
    
    /* Read original argv to copy remaining arguments */
    uint64_t orig_argv = args[1];
    uint64_t new_argv[32];  /* Max 32 args should be plenty */
    int new_argc = 0;
    
    /* First two entries: ld-elf and original path */
    new_argv[new_argc++] = ldelf_addr;
    new_argv[new_argc++] = orig_path_addr;
    
    /* Copy remaining original argv entries (skip argv[0]) */
    uint64_t argv_ptr;
    int orig_idx = 1;  /* Start from argv[1] */
    while (new_argc < 31) {
        errno = 0;
        argv_ptr = ptrace(PTRACE_PEEKDATA, pid, (void *)(orig_argv + orig_idx * 8), NULL);
        if (errno != 0) {
            BSD_WARN("rewrite_jailed_execve: failed to read argv[%d]", orig_idx);
            break;
        }
        new_argv[new_argc++] = argv_ptr;
        if (argv_ptr == 0) break;  /* NULL terminator */
        orig_idx++;
    }
    
    /* Ensure NULL terminator */
    if (new_argc > 0 && new_argv[new_argc - 1] != 0) {
        new_argv[new_argc++] = 0;
    }
    
    /* Write new argv array */
    if (interceptor_write_mem(pid, new_argv, (void *)new_argv_addr, new_argc * 8) < 0) {
        BSD_ERROR("rewrite_jailed_execve: failed to write new argv");
        return -1;
    }
    
    /* Update execve arguments */
    args[0] = ldelf_addr;      /* path = /libexec/ld-elf.so.1 */
    args[1] = new_argv_addr;   /* argv = [ld-elf, orig_path, ...] */
    /* args[2] (envp) stays the same */
    
    BSD_INFO("rewrite_jailed_execve: rewrote to: %s %s", ldelf, path_buf);
    
    return 1;
}

/*
 * Translate FreeBSD absolute paths to use the FreeBSD root filesystem.
 * Returns the argument index that was modified, or -1 if no translation needed.
 */
static int translate_freebsd_path(pid_t pid, int syscall_nr, uint64_t *args) {
    const char *freebsd_root = bsdulator_get_freebsd_root();
    BSD_WARN("translate_freebsd_path called for syscall %d", syscall_nr);
    if (!freebsd_root || freebsd_root[0] == '\0') {
        return -1;
    }
    
    /*
     * CRITICAL: Skip path translation for processes inside a jail!
     * After jail_attach + chroot, the process is already inside the jail's
     * root filesystem. Translating paths would prepend the freebsd_root again,
     * resulting in paths like ./freebsd-root/bin/sh when /bin/sh is correct.
     */
    int jid = jail_get_process_jid(pid);
    if (jid > 0) {
        BSD_TRACE("translate_freebsd_path: skipping for jailed process (jid=%d)", jid);
        return -1;
    }

    /* Determine which argument contains the path based on syscall */
    int path_arg = -1;
    
    switch (syscall_nr) {
        /* Syscalls with path at args[0] */
        case FBSD_SYS_open:
        case FBSD_SYS_access:
        case FBSD_SYS_eaccess:
        case FBSD_SYS_chdir:
        case FBSD_SYS_chroot:
        case FBSD_SYS_mkdir:
        case FBSD_SYS_rmdir:
        case FBSD_SYS_unlink:
        case FBSD_SYS_link:
        case FBSD_SYS_symlink:
        case FBSD_SYS_readlink:
        case FBSD_SYS_execve:
        case FBSD_SYS_chmod:
        case FBSD_SYS_chown:
        case FBSD_SYS_lchown:
        case FBSD_SYS_statfs:
        case FBSD_SYS_rename:
            path_arg = 0;
            break;
        
        /* *at syscalls with path at args[1] (args[0] is dirfd) */
        case FBSD_SYS_openat:
        case FBSD_SYS_faccessat:
        case FBSD_SYS_fchmodat:
        case FBSD_SYS_fchownat:
        case FBSD_SYS_mkdirat:
        case FBSD_SYS_mknodat:
        case FBSD_SYS_unlinkat:
        case FBSD_SYS_readlinkat:
        case FBSD_SYS_symlinkat:
        case FBSD_SYS_linkat:
        case FBSD_SYS_renameat:
        case FBSD_SYS_utimensat:
        case FBSD_SYS_futimesat:
        case FBSD_SYS_fstatat:
            path_arg = 1;
            break;
            
        default:
            return -1;
    }

    if (path_arg < 0) {
        return -1;
    }

    /* Read the path from child's memory */
    char path_buf[1024];
    ssize_t path_len = interceptor_read_string(pid, path_buf, 
                                                (const void *)args[path_arg],
                                                sizeof(path_buf));
    BSD_WARN("path_translate: syscall=%d arg=%d addr=0x%lx len=%zd path='%s'", 
             syscall_nr, path_arg, (unsigned long)args[path_arg], path_len, 
             path_len > 0 ? path_buf : "(failed)");
    if (path_len <= 0) {
        return -1;
    }

    /* Only translate absolute paths */
    if (path_buf[0] != '/') {
        return -1;
    }

    /* Check if it's a path we should translate */
    int should_translate = 0;
    if (strncmp(path_buf, "/libexec/", 9) == 0 ||
        strncmp(path_buf, "/lib/", 5) == 0 ||
        strncmp(path_buf, "/usr/lib/", 9) == 0 ||
        strncmp(path_buf, "/usr/libexec/", 13) == 0 ||
        strncmp(path_buf, "/usr/share/", 11) == 0 ||
        strncmp(path_buf, "/etc/", 5) == 0 ||
        strncmp(path_buf, "/var/", 5) == 0 ||
        strncmp(path_buf, "/bin/", 5) == 0 ||
        strncmp(path_buf, "/sbin/", 6) == 0 ||
        strncmp(path_buf, "/usr/bin/", 9) == 0 ||
        strncmp(path_buf, "/usr/sbin/", 10) == 0 ||
        strncmp(path_buf, "/rescue/", 8) == 0 ||
        strncmp(path_buf, "/tmp/", 5) == 0) {
        should_translate = 1;
    }  

    if (!should_translate) {
        return -1;
    }

    /* Build the translated path */
    char new_path[2048];
    size_t root_len = strlen(freebsd_root);
    
    /* Remove trailing slash from root if present */
    if (root_len > 0 && freebsd_root[root_len - 1] == '/') {
        root_len--;
    }
    
    snprintf(new_path, sizeof(new_path), "%.*s%s", (int)root_len, freebsd_root, path_buf);
    
    BSD_WARN("Path translation: '%s' -> '%s'", path_buf, new_path);

    /* Write the new path to the child's stack */
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("Failed to get regs for path translation");
        return -1;
    }

    /* Allocate space on child's stack (aligned to 16 bytes) */
    size_t new_path_len = strlen(new_path) + 1;
    uint64_t new_path_addr = (regs.rsp - new_path_len - 128) & ~0xFULL;

    /* Write the new path to child's memory */
    ssize_t written = interceptor_write_mem(pid, new_path, (void *)new_path_addr, new_path_len);
    if (written < 0) {
        BSD_ERROR("Failed to write translated path to child memory");
        return -1;
    }

    /* Update the argument to point to the new path */
    args[path_arg] = new_path_addr;
    BSD_INFO("Translated path arg[%d]: '%s' -> '%s' @ 0x%lx",
             path_arg, path_buf, new_path, new_path_addr);
    return path_arg;
}

/* Track forked children that need TLS setup */
static pid_t pending_children[32] = {0};
static int pending_count = 0;

/*
 * Process table to track ALL active processes (main + children)
 * This enables proper handling of multi-pipe commands like: echo | cat | cat
 */
typedef struct {
    pid_t pid;
    int active;          /* 1 = alive, 0 = exited */
    int in_syscall;      /* Toggle for syscall entry/exit */
    int skip_post_exec;  /* Skip phantom syscall stop after exec (per-process!) */
} process_entry_t;

static process_entry_t process_table[64];
static int process_count = 0;
static pid_t main_pid = 0;  /* Track original/main process */

/* Find process entry by PID */
static process_entry_t* find_process(pid_t pid) {
    for (int i = 0; i < process_count; i++) {
        if (process_table[i].pid == pid) return &process_table[i];
    }
    return NULL;
}

/* Add a new process to the table */
static process_entry_t* add_process(pid_t pid) {
    process_entry_t *entry = find_process(pid);
    if (entry) {
        entry->active = 1;
        return entry;
    }
    if (process_count < 64) {
        entry = &process_table[process_count++];
        entry->pid = pid;
        entry->active = 1;
        entry->in_syscall = 0;
        BSD_TRACE("Added process %d to table (count=%d)", pid, process_count);
        return entry;
    }
    return NULL;
}

/* Mark a process as exited */
static void remove_process(pid_t pid) {
    process_entry_t *entry = find_process(pid);
    if (entry) {
        entry->active = 0;
        BSD_TRACE("Marked process %d as exited", pid);
    }
}

/* Count active processes */
static int count_active_processes(void) {
    int count = 0;
    for (int i = 0; i < process_count; i++) {
        if (process_table[i].active) count++;
    }
    return count;
}

/* Check if a process is active */
static int is_process_active(pid_t pid) {
    process_entry_t *entry = find_process(pid);
    return entry && entry->active;
}

/* Get in_syscall state for a process */
static int get_in_syscall(pid_t pid) {
    process_entry_t *entry = find_process(pid);
    return entry ? entry->in_syscall : 0;
}

/* Set in_syscall state for a process */
static void set_in_syscall(pid_t pid, int val) {
    process_entry_t *entry = find_process(pid);
    if (entry) {
        entry->in_syscall = val;
    } else {
        /* Auto-add if not found */
        entry = add_process(pid);
        if (entry) entry->in_syscall = val;
    }
}

/* Get skip_post_exec state for a process */
static int get_skip_post_exec(pid_t pid) {
    process_entry_t *entry = find_process(pid);
    return entry ? entry->skip_post_exec : 0;
}

/* Set skip_post_exec state for a process */
static void set_skip_post_exec(pid_t pid, int val) {
    process_entry_t *entry = find_process(pid);
    if (entry) {
        entry->skip_post_exec = val;
    } else {
        entry = add_process(pid);
        if (entry) entry->skip_post_exec = val;
    }
}

int interceptor_wait(interceptor_state_t *state) {
    int status;
    pid_t result;
    
    result = waitpid(-1, &status, 0);
    
    /* Update pid to the process that actually stopped */
    if (result > 0) {
        state->pid = result;
        
        /* Auto-add to process table if not already there */
        if (!find_process(result)) {
            add_process(result);
        }
        
        /* Check if this is a newly forked child needing TLS setup */
        for (int i = 0; i < pending_count; i++) {
            if (pending_children[i] == result) {
                BSD_INFO("Forked child PID %d detected - TLS inherited from parent", result);
                /* TLS inherited from parent - dont reallocate */
                pending_children[i] = pending_children[--pending_count];
                break;
            }
        }
    }
    if (result < 0) {
        if (errno == ECHILD) {
            state->running = false;
            state->last_event = EVENT_EXIT;
            return 0;
        }
        BSD_ERROR("waitpid() failed: %s", strerror(errno));
        return -1;
    }
    
    if (WIFEXITED(status)) {
        BSD_INFO("Process %d exited with code %d", state->pid, WEXITSTATUS(status));
        
        /* Mark this process as exited in our table */
        remove_process(state->pid);
        
        if (state->pid == main_pid) {
            /* Main process exited - we're done */
            state->running = false;
            state->last_event = EVENT_EXIT;
            state->exit_code = WEXITSTATUS(status);
            BSD_TRACE("Main process exited with code %d", state->exit_code);
            return 0;
        }
        
        /* A child exited - check if there are other active processes */
        int active = count_active_processes();
        BSD_INFO("Child %d exited, %d active processes remaining", state->pid, active);
        
        if (active == 0) {
            /* No more processes - we're done */
            state->running = false;
            state->last_event = EVENT_EXIT;
            state->exit_code = 0;
            return 0;
        }
        
        /* More processes exist - just continue, waitpid will get the next event */
        state->last_event = EVENT_NONE;
        return 0;
    }
    
    if (WIFSIGNALED(status)) {
        BSD_INFO("Process %d killed by signal %d", state->pid, WTERMSIG(status));
        
        /* Mark this process as exited */
        remove_process(state->pid);
        
        if (state->pid == main_pid) {
            state->running = false;
            state->last_event = EVENT_EXIT;
            state->exit_code = 128 + WTERMSIG(status);
            BSD_TRACE("Main process killed by signal %d", WTERMSIG(status));
            return 0;
        }
        
        /* A child was killed - check remaining processes */
        int active = count_active_processes();
        BSD_INFO("Child %d killed, %d active processes remaining", state->pid, active);
        
        if (active == 0) {
            state->running = false;
            state->last_event = EVENT_EXIT;
            state->exit_code = 128 + WTERMSIG(status);
            return 0;
        }
        
        /* More processes exist - continue */
        state->last_event = EVENT_NONE;
        return 0;
    }
    
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        
        /* Syscall stop (SIGTRAP | 0x80) */
        if (sig == (SIGTRAP | 0x80)) {
            /* Skip phantom syscall stop after exec - use per-process flag! */
            if (get_skip_post_exec(state->pid)) {
                BSD_TRACE("Skipping post-exec syscall stop for PID %d", state->pid);
                set_skip_post_exec(state->pid, 0);
                state->last_event = EVENT_NONE;  /* Ignored event */
                return 0;
            }
            
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, state->pid, NULL, &regs) < 0) {
                BSD_ERROR("Failed to get registers: %s", strerror(errno));
                return -1;
            }
            
            set_in_syscall(state->pid, !get_in_syscall(state->pid));
            
            if (get_in_syscall(state->pid)) {
                state->last_event = EVENT_SYSCALL_ENTER;
                state->syscall_nr = regs.orig_rax;
                state->args[0] = regs.rdi;
                state->args[1] = regs.rsi;
                state->args[2] = regs.rdx;
                state->args[3] = regs.r10;
                state->args[4] = regs.r8;
                state->args[5] = regs.r9;
            } else {
                state->last_event = EVENT_SYSCALL_EXIT;
                state->retval = (int64_t)regs.rax;
            }
            
            return 0;
        }
        
        /* ptrace events */
        if (sig == SIGTRAP) {
            unsigned int event = (unsigned int)status >> 16;
            switch (event) {
                case PTRACE_EVENT_FORK: {
                    /* Check if THIS process is a pending child (child side of fork) */
                    for (int i = 0; i < pending_count; i++) {
                        if (pending_children[i] == state->pid) {
                            BSD_INFO("Forked child PID %d detected - TLS inherited from parent", state->pid);
                            /* TLS inherited from parent - dont reallocate */
                            pending_children[i] = pending_children[--pending_count];
                            break;
                        }
                    }
                    unsigned long child_pid;
                    ptrace(PTRACE_GETEVENTMSG, state->pid, NULL, &child_pid);
                    BSD_INFO("Fork event: child PID = %lu", child_pid);
                    
                    /* Add child to process table */
                    add_process((pid_t)child_pid);
                    
                    if (pending_count < 32) { 
                        pending_children[pending_count++] = child_pid; 
                        BSD_INFO("Added child %lu to pending list (count=%d)", child_pid, pending_count); 
                    }
                    /* Set up ptrace options for child */
                    ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_OPTIONS);
                    state->last_event = EVENT_FORK;
                    BSD_TRACE("Fork event");
                }
                    break;
                case PTRACE_EVENT_VFORK: {
                    unsigned long child_pid;
                    ptrace(PTRACE_GETEVENTMSG, state->pid, NULL, &child_pid);
                    BSD_INFO("Vfork event: child PID = %lu", child_pid);
                    
                    /* Add child to process table */
                    add_process((pid_t)child_pid);
                    
                    if (pending_count < 32) { 
                        pending_children[pending_count++] = child_pid; 
                    }
                    ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_OPTIONS);
                    state->last_event = EVENT_VFORK;
                    BSD_TRACE("Vfork event");
                }
                    break;
                case PTRACE_EVENT_CLONE: {
                    unsigned long clone_child_pid;
                    ptrace(PTRACE_GETEVENTMSG, state->pid, NULL, &clone_child_pid);
                    BSD_INFO("Clone event: child PID = %lu", clone_child_pid);
                    
                    /* Add child to process table */
                    add_process((pid_t)clone_child_pid);
                    
                    if (pending_count < 32) { 
                        pending_children[pending_count++] = clone_child_pid; 
                        BSD_INFO("Added clone child %lu to pending list (count=%d)", clone_child_pid, pending_count); 
                    }
                    ptrace(PTRACE_SETOPTIONS, clone_child_pid, NULL, PTRACE_OPTIONS);
                    state->last_event = EVENT_CLONE;
                }
                    break;
                case PTRACE_EVENT_EXEC: {
                    state->last_event = EVENT_EXEC;
                    BSD_INFO("Exec event for PID %d - setting up FreeBSD environment", state->pid);
                    set_in_syscall(state->pid, 0);
                    set_skip_post_exec(state->pid, 1);  /* Per-process flag! */
                    
                    /*
                     * CRITICAL: Skip all FreeBSD environment setup for jailed processes!
                     * After jail_attach + chroot, the process is already inside the jail's
                     * FreeBSD root filesystem. The TLS setup, stack fixup, argv0 translation,
                     * and auxv rewriting would all corrupt the jailed process's state because:
                     * 1. TLS addresses from the outer process don't apply inside the jail
                     * 2. Stack alignment is already correct for the new exec
                     * 3. Path translation would create invalid paths inside the chroot
                     * 4. Auxv rewriting would corrupt AT_EXECPATH and other pointers
                     */
                    int exec_jid = jail_get_process_jid(state->pid);
                    if (exec_jid > 0) {
                        BSD_INFO("Exec inside jail (jid=%d) - doing minimal FreeBSD setup", exec_jid);
                        /*
                         * For jailed processes, we still need TLS, stack fixup, and auxv,
                         * but we skip:
                         * - Hardcoded global writes (addresses differ per binary)
                         * - Path translation (paths are correct inside chroot)
                         * - argv0 fixes (not needed inside jail)
                         */
                        if (setup_freebsd_tls_ex(state->pid, 1) < 0) {  /* skip_globals=1 */
                            BSD_WARN("Failed to setup FreeBSD TLS for jailed process");
                        }
                        fixup_freebsd_entry(state->pid);
                        /* Jailed processes still need auxv rewriting for FreeBSD format */
                        if (freebsd_setup_stack(state->pid, 0, 0, 0, 0) < 0) {
                            BSD_WARN("Failed to setup FreeBSD stack for jailed process");
                        }
                    } else {
                        /* Set up FreeBSD TLS BEFORE the binary starts */
                        if (setup_freebsd_tls(state->pid) < 0) {
                            BSD_WARN("Failed to setup FreeBSD TLS");
                        }
                        
                        /* Fix up stack alignment FIRST, before writing auxv */
                        fixup_freebsd_entry(state->pid);
                        
                        /* Fix argv[0] to contain translated path for multi-call binaries */
                        if (fix_argv0_after_exec(state->pid) < 0) {
                            BSD_WARN("Failed to fix argv[0] after exec");
                        }
                        
                        /* Now rewrite auxv with correct pointers based on realigned RSP */
                        if (freebsd_setup_stack(state->pid, 0, 0, 0, 0) < 0) {
                            BSD_WARN("Failed to setup FreeBSD stack environment");
                        }
                    }
                    break;
                }
                default:
                    state->last_event = EVENT_SIGNAL;
                    state->signal = SIGTRAP;
                    break;
            }
            return 0;
        }
        
        /* Regular signal */
        state->last_event = EVENT_SIGNAL;
        state->signal = sig;
        
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, state->pid, NULL, &regs) == 0) {
            BSD_TRACE("Signal %d at RIP=0x%llx RSP=0x%llx", 
                    sig, (unsigned long long)regs.rip, 
                    (unsigned long long)regs.rsp);
            if (sig == SIGSEGV || sig == SIGBUS) {
                BSD_ERROR("CRASH: Signal %d at RIP=0x%llx",
                        sig, (unsigned long long)regs.rip);
                BSD_ERROR("  RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx",
                        (unsigned long long)regs.rax,
                        (unsigned long long)regs.rbx,
                        (unsigned long long)regs.rcx,
                        (unsigned long long)regs.rdx);
                BSD_ERROR("  RSI=0x%llx RDI=0x%llx RSP=0x%llx RBP=0x%llx",
                        (unsigned long long)regs.rsi,
                        (unsigned long long)regs.rdi,
                        (unsigned long long)regs.rsp,
                        (unsigned long long)regs.rbp);
            }
        }
        return 0;
    }
    
    BSD_WARN("Unexpected wait status: 0x%x", status);
    return 0;
}

int interceptor_continue(interceptor_state_t *state) {
    /* Verify the process is still active before trying to continue it */
    if (!is_process_active(state->pid)) {
        BSD_TRACE("Process %d is not active, skipping continue", state->pid);
        return 0;
    }
    
    if (ptrace(PTRACE_SYSCALL, state->pid, NULL, NULL) < 0) {
        if (errno == ESRCH) {
            /* Process no longer exists - mark as exited and continue */
            BSD_INFO("Process %d no longer exists (ESRCH), marking as exited", state->pid);
            remove_process(state->pid);
            return 0;
        }
        BSD_ERROR("ptrace(SYSCALL) failed for pid %d: %s", state->pid, strerror(errno));
        return -1;
    }
    return 0;
}

int interceptor_continue_signal(interceptor_state_t *state, int signal) {
    /* Verify the process is still active before trying to continue it */
    if (!is_process_active(state->pid)) {
        BSD_TRACE("Process %d is not active, skipping continue_signal", state->pid);
        return 0;
    }
    
    if (ptrace(PTRACE_SYSCALL, state->pid, NULL, signal) < 0) {
        if (errno == ESRCH) {
            BSD_INFO("Process %d no longer exists (ESRCH), marking as exited", state->pid);
            remove_process(state->pid);
            return 0;
        }
        BSD_ERROR("ptrace(SYSCALL) failed for pid %d: %s", state->pid, strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * Track pending mmap info for alignment fixup
 * These are per-interceptor state, not thread-local since we're in the tracer
 */
static size_t pending_mmap_alignment = 0;
static size_t pending_mmap_orig_size = 0;
static uint64_t pending_mmap_alloc_size = 0;

/*
 * Fix mmap alignment after syscall returns.
 * FreeBSD MAP_ALIGNED(n) requests 2^n byte alignment.
 * Linux doesn't support this, so we over-allocate and carve out an aligned region.
 * 
 * Note: pid is reserved for future use (syscall injection to reclaim wasted memory)
 */
static long fixup_mmap_alignment(pid_t pid __attribute__((unused)), 
                                 long mmap_result, size_t alignment, size_t orig_size) {
    if (mmap_result < 0 && mmap_result > -4096) {
        /* Error return, don't fix up */
        return mmap_result;
    }
    
    uint64_t addr = (uint64_t)mmap_result;
    
    /* Check if already aligned */
    if ((addr % alignment) == 0) {
        BSD_TRACE("mmap alignment: addr 0x%lx already aligned to 0x%lx",
                  (unsigned long)addr, (unsigned long)alignment);
        /* Unmap excess at the end if we over-allocated */
        if (pending_mmap_alloc_size > orig_size) {
            size_t excess = pending_mmap_alloc_size - orig_size;
            uint64_t excess_addr = addr + orig_size;
            BSD_TRACE("mmap alignment: unmapping excess %zu bytes at 0x%lx",
                      excess, (unsigned long)excess_addr);
            /* We'd need to inject munmap here - for now just leave it */
        }
        return mmap_result;
    }
    
    /* Calculate aligned address within the allocation */
    uint64_t aligned_addr = (addr + alignment - 1) & ~(alignment - 1);
    size_t leading_waste = aligned_addr - addr;
    
    BSD_TRACE("mmap alignment: addr 0x%lx -> aligned 0x%lx (waste %zu)",
              (unsigned long)addr, (unsigned long)aligned_addr, leading_waste);
    
    /* 
     * We need to:
     * 1. munmap the leading portion [addr, aligned_addr)
     * 2. munmap the trailing portion [aligned_addr + orig_size, addr + alloc_size)
     * 
     * However, injecting syscalls is complex during syscall-exit.
     * For now, we'll just return the aligned address and accept some memory waste.
     * A proper implementation would use syscall injection.
     */
    
    BSD_WARN("mmap alignment: returning aligned addr 0x%lx (memory leak: %zu bytes)",
             (unsigned long)aligned_addr, leading_waste);
    
    return (long)aligned_addr;
}

/* Main interception loop */
int interceptor_run(interceptor_state_t *state) {
    /* Initialize process table */
    memset(process_table, 0, sizeof(process_table));
    process_count = 0;
    
    main_pid = state->pid;  /* Set global main_pid */
    add_process(main_pid);  /* Add main process to table */
    
    BSD_INFO("Starting syscall interception for PID %d", (int)state->pid);
    
    /* Initialize state - per-process flags are initialized in add_process() */
    set_in_syscall(state->pid, 0);
    set_skip_post_exec(state->pid, 0);
    pending_mmap_alignment = 0;
    pending_mmap_orig_size = 0;
    pending_mmap_alloc_size = 0;
    
    if (interceptor_continue(state) < 0) {
        return -1;
    }
    
    while (state->running) {
        if (interceptor_wait(state) < 0) {
            return -1;
        }
        
        switch (state->last_event) {
            case EVENT_NONE:
                /* Ignored event (e.g., child exited, skipped post-exec) */
                /* The process may still be stopped - need to continue it */
                if (is_process_active(state->pid)) {
                    if (interceptor_continue(state) < 0) {
                        return -1;
                    }
                }
                /* Loop back to waitpid for the next event */
                continue;
                
            case EVENT_SYSCALL_ENTER: {
                state->syscall_count++;
                
                int linux_nr;
                syscall_result_t result = syscall_translate((int)state->syscall_nr, &linux_nr);
                
                const char *name = syscall_name((int)state->syscall_nr);
                BSD_WARN("ENTER FreeBSD syscall %llu (%s) -> Linux %d",
                          (unsigned long long)state->syscall_nr,
                          name ? name : "unknown",
                          linux_nr);
                
                /* Special logging for readlink to debug ENOENT causing abort */
                if ((int)state->syscall_nr == FBSD_SYS_readlink) {
                    char path_buf[512];
                    ssize_t path_len = interceptor_read_string(state->pid, path_buf, 
                                                               (const void *)state->args[0], 
                                                               sizeof(path_buf));
                    if (path_len > 0) {
                        BSD_INFO("==> readlink: path='%s'", path_buf);
                    } else {
                        BSD_INFO("==> readlink: could not read path from 0x%lx", 
                                 (unsigned long)state->args[0]);
                    }
                }
                
                /* Translate FreeBSD system paths to use FreeBSD root */
                int path_translated = translate_freebsd_path(state->pid,
                                                              (int)state->syscall_nr,
                                                              state->args);
                if (path_translated >= 0) {
                    /* Path was translated, need to update args in child */
                    if (interceptor_set_args(state->pid, state->args) < 0) {
                        BSD_ERROR("Failed to set translated path args");
                    }
                }
                
                /*
                 * Special handling for execve in jailed processes:
                 * Rewrite execve to go through the dynamic linker because
                 * Linux can't find the FreeBSD interpreter inside the chroot.
                 */
                if ((int)state->syscall_nr == FBSD_SYS_execve) {
                    int rewritten = rewrite_jailed_execve(state->pid, state->args);
                    if (rewritten > 0) {
                        /* Execve was rewritten, update args in child */
                        if (interceptor_set_args(state->pid, state->args) < 0) {
                            BSD_ERROR("Failed to set rewritten execve args");
                        }
                    }
                }

                switch (result) {
                    case SYSCALL_TRANSLATED:
                    case SYSCALL_PASSTHROUGH:
                        if (linux_nr >= 0 && linux_nr != (int)state->syscall_nr) {
                            BSD_TRACE("  Translating %llu -> %d",
                                      (unsigned long long)state->syscall_nr, linux_nr);
                            if (interceptor_set_syscall(state->pid, (uint64_t)linux_nr) < 0) {
                                BSD_ERROR("Failed to set syscall number");
                            }
                        }
                        
                        if (syscall_translate_args((int)state->syscall_nr, state->args) != 0) {
                            if (interceptor_set_args(state->pid, state->args) < 0) {
                                BSD_ERROR("Failed to set syscall args");
                            }
                        }
                        
                        /*
                         * Special handling for mmap with MAP_ALIGNED.
                         * After abi_translate_mmap_flags(), check if alignment was requested.
                         * If so, we need to over-allocate to ensure we can find an aligned region.
                         */
                        if ((int)state->syscall_nr == FBSD_SYS_mmap) {
                            BSD_WARN("mmap args: addr=0x%lx len=%lu prot=0x%lx flags=0x%lx fd=%d offset=%lu",
                                     state->args[0], state->args[1], state->args[2],
                                     state->args[3], (int)state->args[4], state->args[5]);
                        }
                        if ((int)state->syscall_nr == FBSD_SYS_mmap) {
                            pending_mmap_alignment = abi_get_pending_mmap_alignment();
                            if (pending_mmap_alignment > 0) {
                                pending_mmap_orig_size = state->args[1];  /* Original size */
                                /* Over-allocate: size + alignment to guarantee aligned region */
                                pending_mmap_alloc_size = pending_mmap_orig_size + pending_mmap_alignment;
                                state->args[1] = pending_mmap_alloc_size;
                                BSD_TRACE("mmap: over-allocating for alignment: %zu -> %llu",
                                          pending_mmap_orig_size, (unsigned long long)pending_mmap_alloc_size);
                                if (interceptor_set_args(state->pid, state->args) < 0) {
                                    BSD_ERROR("Failed to set mmap over-allocation size");
                                }
                            } else {
                                pending_mmap_orig_size = 0;
                                pending_mmap_alloc_size = 0;
                            }
                        }
                        
                        state->translated_count++;
                        break;
                        
                    case SYSCALL_EMULATED: {
                        BSD_TRACE("  Emulating syscall %llu (%s)",
                                  (unsigned long long)state->syscall_nr,
                                  name ? name : "unknown");
                        long ret = syscall_execute(state->pid, (int)state->syscall_nr, state->args);
                        if (ret == -EAGAIN) {
                            /* Special: syscall was rewritten, let it execute normally */
                            BSD_INFO("Emulated syscall rewrote registers, executing normally");
                            state->translated_count++;
                        } else {
                            interceptor_skip_syscall(state->pid, ret);
                            state->emulated_count++;
                        }
                        break;
                    }
                    
                    case SYSCALL_UNSUPPORTED:
                        BSD_WARN("Unsupported syscall %llu (%s)",
                                 (unsigned long long)state->syscall_nr,
                                 name ? name : "unknown");
                        interceptor_skip_syscall(state->pid, -ENOSYS);
                        state->failed_count++;
                        break;
                        
                    case SYSCALL_SKIP:
                        interceptor_skip_syscall(state->pid, 0);
                        break;
                }
                break;
            }
            
            case EVENT_SYSCALL_EXIT: {
                BSD_TRACE("EXIT syscall %llu = %lld (0x%llx)",
                          (unsigned long long)state->syscall_nr,
                          (long long)state->retval,
                          (unsigned long long)state->retval);
                
                /* Monitor __stack_chk_guard for changes */
                {
                    errno = 0;
                    uint64_t current_guard = ptrace(PTRACE_PEEKDATA, state->pid, 
                                                    (void*)0x180b5a0, NULL);
                    if (errno == 0) {
                        uint64_t expected;
                        memcpy(&expected, g_freebsd_runtime.canary, sizeof(expected));
                        if (current_guard != expected) {
                            BSD_ERROR("__stack_chk_guard CHANGED! expected=0x%lx actual=0x%lx",
                                      expected, current_guard);
                        }
                    }
                }
                
                /*
                 * Special handling for mmap alignment fixup.
                 * If we over-allocated for alignment, fix up the return address.
                 */
                if ((int)state->syscall_nr == FBSD_SYS_mmap && pending_mmap_alignment > 0) {
                    long fixed_ret = fixup_mmap_alignment(state->pid, state->retval,
                                                          pending_mmap_alignment,
                                                          pending_mmap_orig_size);
                    if (fixed_ret != state->retval) {
                        BSD_TRACE("mmap alignment fixup: 0x%llx -> 0x%lx",
                                  (unsigned long long)state->retval, fixed_ret);
                        interceptor_set_return(state->pid, fixed_ret);
                        state->retval = fixed_ret;
                    }
                    /* Clear alignment tracking */
                    pending_mmap_alignment = 0;
                    pending_mmap_orig_size = 0;
                    pending_mmap_alloc_size = 0;
                    abi_clear_pending_mmap_alignment();
                }

                /*
                 * Stat structure translation for fstat/fstatat
                 * After successful stat syscalls, translate Linux stat to FreeBSD format
                 */
                if (state->retval >= 0) {
                    uint64_t stat_buf_addr = 0;
                    int needs_translation = 0;
                    
                    if ((int)state->syscall_nr == FBSD_SYS_fstat) {
                        /* fstat(fd, stat_buf) - arg[1] is buffer */
                        stat_buf_addr = state->args[1];
                        needs_translation = 1;
                    } else if ((int)state->syscall_nr == FBSD_SYS_fstatat) {
                        /* fstatat(fd, path, stat_buf, flags) - arg[2] is buffer */
                        stat_buf_addr = state->args[2];
                        needs_translation = 1;
                    }
                    
                    if (needs_translation && stat_buf_addr != 0) {
                    /* Read Linux stat from child memory */
                    uint8_t linux_stat[144];
                    struct iovec local_iov = { linux_stat, sizeof(linux_stat) };
                    struct iovec remote_iov = { (void *)stat_buf_addr, sizeof(linux_stat) };

                    ssize_t nread = process_vm_readv(state->pid, &local_iov, 1, &remote_iov, 1, 0);
                    if (nread == sizeof(linux_stat)) {
                    /* Translate to FreeBSD format */
                    fbsd_stat_t fbsd_stat;
                    abi_translate_stat_to_freebsd(linux_stat, &fbsd_stat);

                    /* Write FreeBSD stat back to child memory */
                    struct iovec local_out = { &fbsd_stat, sizeof(fbsd_stat) };
                    struct iovec remote_out = { (void *)stat_buf_addr, sizeof(fbsd_stat) };

                    ssize_t nwritten = process_vm_writev(state->pid, &local_out, 1, &remote_out, 1, 0);
                    if (nwritten > 0) {
                    BSD_TRACE("Translated stat buffer at 0x%lx (%zd bytes)",
                    stat_buf_addr, nwritten);
                    }
                    }
                    }
                    }

                /*
                 * Statfs structure translation for fstatfs
                 * DISABLED: We now emulate fstatfs in syscall_table.c
                 * This code was overwriting our correct emulated data
                 */
                #if 0  /* Disabled - using emulation instead */
                if (state->retval >= 0 && (int)state->syscall_nr == FBSD_SYS_fstatfs) {
                    uint64_t statfs_buf_addr = state->args[1];
                    
                    if (statfs_buf_addr != 0) {
                        /* Read Linux statfs from child memory (120 bytes) */
                        uint8_t linux_statfs[120];
                        struct iovec local_iov = { linux_statfs, sizeof(linux_statfs) };
                        struct iovec remote_iov = { (void *)statfs_buf_addr, sizeof(linux_statfs) };
                        
                        ssize_t nread = process_vm_readv(state->pid, &local_iov, 1, &remote_iov, 1, 0);
                        if (nread >= 80) {  /* At least enough to get the key fields */
                            /* Extract Linux statfs fields */
                            uint64_t f_type, f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree;
                            uint64_t f_fsid_lo, f_namelen;
                            
                            memcpy(&f_type, linux_statfs + 0, 8);
                            memcpy(&f_bsize, linux_statfs + 8, 8);
                            memcpy(&f_blocks, linux_statfs + 16, 8);
                            memcpy(&f_bfree, linux_statfs + 24, 8);
                            memcpy(&f_bavail, linux_statfs + 32, 8);
                            memcpy(&f_files, linux_statfs + 40, 8);
                            memcpy(&f_ffree, linux_statfs + 48, 8);
                            memcpy(&f_fsid_lo, linux_statfs + 56, 8);
                            memcpy(&f_namelen, linux_statfs + 64, 8);
                            
                            BSD_TRACE("fstatfs: Linux type=0x%lx bsize=%lu blocks=%lu",
                                      (unsigned long)f_type, (unsigned long)f_bsize,
                                      (unsigned long)f_blocks);
                            
                            /* Build FreeBSD statfs structure (2344 bytes) */
                            uint8_t fbsd_statfs[2344];
                            memset(fbsd_statfs, 0, sizeof(fbsd_statfs));
                            
                            size_t off = 0;
                            
                            /* f_version (4 bytes) */
                            uint32_t version = 0x20140518;
                            memcpy(fbsd_statfs + off, &version, 4); off += 4;
                            
                            /* f_type (4 bytes) */
                            uint32_t type32 = (uint32_t)f_type;
                            memcpy(fbsd_statfs + off, &type32, 4); off += 4;
                            
                            /* f_flags (8 bytes) */
                            uint64_t flags = 0;
                            memcpy(fbsd_statfs + off, &flags, 8); off += 8;
                            
                            /* f_bsize (8 bytes) */
                            memcpy(fbsd_statfs + off, &f_bsize, 8); off += 8;
                            
                            /* f_iosize (8 bytes) */
                            memcpy(fbsd_statfs + off, &f_bsize, 8); off += 8;
                            
                            /* f_blocks (8 bytes) */
                            memcpy(fbsd_statfs + off, &f_blocks, 8); off += 8;
                            
                            /* f_bfree (8 bytes) */
                            memcpy(fbsd_statfs + off, &f_bfree, 8); off += 8;
                            
                            /* f_bavail (8 bytes) */
                            memcpy(fbsd_statfs + off, &f_bavail, 8); off += 8;
                            
                            /* f_files (8 bytes) */
                            memcpy(fbsd_statfs + off, &f_files, 8); off += 8;
                            
                            /* f_ffree (8 bytes) */
                            memcpy(fbsd_statfs + off, &f_ffree, 8); off += 8;
                            
                            /* f_syncwrites, f_asyncwrites, f_syncreads, f_asyncreads (4 x 8 = 32 bytes) */
                            off += 32;
                            
                            /* f_nvnodelistsize (4 bytes) + f_spare0 (4 bytes) */
                            off += 8;
                            
                            /* f_spare[9] (72 bytes) */
                            off += 72;
                            
                            /* f_namemax (4 bytes) */
                            uint32_t namemax = (uint32_t)f_namelen;
                            memcpy(fbsd_statfs + off, &namemax, 4); off += 4;
                            
                            /* f_owner (4 bytes) */
                            off += 4;
                            
                            /* f_fsid (8 bytes) */
                            memcpy(fbsd_statfs + off, &f_fsid_lo, 8); off += 8;
                            
                            /* f_charspare (80 bytes) */
                            off += 80;
                            
                            /* f_fstypename (16 bytes) */
                            strncpy((char *)(fbsd_statfs + off), "unknown", 16);
                            off += 16;
                            
                            /* f_mntfromname (1024 bytes) */
                            strncpy((char *)(fbsd_statfs + off), "/dev/unknown", 1024);
                            off += 1024;
                            
                            /* f_mntonname (1024 bytes) */
                            strncpy((char *)(fbsd_statfs + off), "/", 1024);
                            off += 1024;
                            
                            BSD_TRACE("fstatfs: Built FreeBSD struct, offset=%zu", off);
                            
                            /* Write FreeBSD statfs back to child memory */
                            struct iovec local_out = { fbsd_statfs, sizeof(fbsd_statfs) };
                            struct iovec remote_out = { (void *)statfs_buf_addr, sizeof(fbsd_statfs) };
                            
                            ssize_t nwritten = process_vm_writev(state->pid, &local_out, 1, &remote_out, 1, 0);
                            if (nwritten > 0) {
                                BSD_TRACE("Translated statfs buffer at 0x%lx (%zd bytes)",
                                          statfs_buf_addr, nwritten);
                                
                                /* Verify what we wrote */
                                uint8_t verify[16];
                                struct iovec v_local = { verify, sizeof(verify) };
                                struct iovec v_remote = { (void *)statfs_buf_addr, sizeof(verify) };
                                if (process_vm_readv(state->pid, &v_local, 1, &v_remote, 1, 0) > 0) {
                                    uint32_t ver;
                                    memcpy(&ver, verify, 4);
                                    BSD_TRACE("fstatfs: Readback version=0x%x (expect 0x20140518)", ver);
                                    BSD_TRACE("fstatfs: First 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                                              verify[0], verify[1], verify[2], verify[3],
                                              verify[4], verify[5], verify[6], verify[7],
                                              verify[8], verify[9], verify[10], verify[11],
                                              verify[12], verify[13], verify[14], verify[15]);
                                }
                                
                                /* Ensure carry flag is clear for FreeBSD success convention */
                                struct user_regs_struct regs;
                                if (ptrace(PTRACE_GETREGS, state->pid, NULL, &regs) == 0) {
                                    regs.eflags &= ~0x1;  /* Clear carry flag */
                                    ptrace(PTRACE_SETREGS, state->pid, NULL, &regs);
                                    BSD_TRACE("fstatfs: Cleared carry flag, eflags=0x%llx",
                                              (unsigned long long)regs.eflags);
                                }
                            } else {
                                BSD_WARN("Failed to write FreeBSD statfs: %s", strerror(errno));
                            }
                        }
                    }
                }
                #endif  /* Disabled fstatfs translation - using emulation */

                /*
                 * Dirent structure translation for getdirentries
                 * After successful getdirentries, translate Linux dirent64 to FreeBSD format
                 */
                if (state->retval > 0 && (int)state->syscall_nr == FBSD_SYS_getdirentries) {
                    /* getdirentries(fd, buf, nbytes, basep) - arg[1] is buffer, retval is bytes read */
                    uint64_t dirent_buf_addr = state->args[1];
                    size_t linux_bytes = (size_t)state->retval;
                    
                    if (dirent_buf_addr != 0 && linux_bytes > 0) {
                        /* Allocate buffers for translation */
                        uint8_t *linux_buf = malloc(linux_bytes);
                        uint8_t *fbsd_buf = malloc(linux_bytes * 2);  /* FreeBSD entries may be larger */
                        
                        if (linux_buf && fbsd_buf) {
                            /* Read Linux dirents from child memory */
                            struct iovec local_iov = { linux_buf, linux_bytes };
                            struct iovec remote_iov = { (void *)dirent_buf_addr, linux_bytes };
                            
                            ssize_t nread = process_vm_readv(state->pid, &local_iov, 1, &remote_iov, 1, 0);
                            if (nread == (ssize_t)linux_bytes) {
                                /* Translate to FreeBSD format */
                                int fbsd_bytes = abi_translate_dirents_to_freebsd(
                                    linux_buf, linux_bytes,
                                    fbsd_buf, linux_bytes * 2);
                                
                                if (fbsd_bytes > 0) {
                                    /* Write FreeBSD dirents back to child memory */
                                    struct iovec local_out = { fbsd_buf, (size_t)fbsd_bytes };
                                    struct iovec remote_out = { (void *)dirent_buf_addr, (size_t)fbsd_bytes };
                                    
                                    ssize_t nwritten = process_vm_writev(state->pid, &local_out, 1, &remote_out, 1, 0);
                                    if (nwritten > 0) {
                                        BSD_TRACE("Translated dirent buffer at 0x%lx: %zd Linux bytes -> %d FreeBSD bytes",
                                                  dirent_buf_addr, linux_bytes, fbsd_bytes);
                                        
                                        /* Update return value to reflect FreeBSD buffer size */
                                        state->retval = fbsd_bytes;
                                        interceptor_set_return(state->pid, fbsd_bytes);
                                    }
                                }
                            }
                        }
                        
                        free(linux_buf);
                        free(fbsd_buf);
                    }
                }

                long new_ret = syscall_translate_return((int)state->syscall_nr, state->retval);
                if (new_ret != state->retval || (state->retval < 0 && state->retval > -4096)) {
                    interceptor_set_return(state->pid, new_ret);
                }
                break;
            }
            
            case EVENT_SIGNAL:
                BSD_TRACE("Signal %d received", state->signal);
                
                if (state->signal == SIGSEGV || state->signal == SIGBUS ||
                    state->signal == SIGILL || state->signal == SIGFPE) {
                    BSD_ERROR("Fatal signal %d - process will be terminated", state->signal);
                    interceptor_continue_signal(state, state->signal);
                    continue;
                }
                
                {
                    int sig = abi_translate_signal_to_freebsd(state->signal);
                    interceptor_continue_signal(state, sig);
                }
                continue;
                
            case EVENT_FORK:
            case EVENT_VFORK:
            case EVENT_CLONE:
                break;
                
            case EVENT_EXEC:
                BSD_INFO("FreeBSD binary loaded, starting syscall translation");
                break;
                
            case EVENT_EXIT:
                continue;
                
            default:
                break;
        }
        
        if (state->running) {
            /* Check if there are still active processes */
            if (count_active_processes() == 0) {
                BSD_INFO("No more active processes, exiting");
                state->running = false;
                continue;
            }
            
            /* Only continue if the current process is still active */
            if (is_process_active(state->pid)) {
                if (interceptor_continue(state) < 0) {
                    return -1;
                }
            }
            /* If current process is not active, the next waitpid will get another process's event */
        }
    }
    
    BSD_INFO("Interception loop ended");
    return 0;
}

void interceptor_print_stats(const interceptor_state_t *state) {
    printf("\n=== BSDulator Statistics ===\n");
    printf("Total syscalls:     %llu\n", (unsigned long long)state->syscall_count);
    printf("Translated:         %llu\n", (unsigned long long)state->translated_count);
    printf("Emulated:           %llu\n", (unsigned long long)state->emulated_count);
    printf("Failed/Unsupported: %llu\n", (unsigned long long)state->failed_count);
    if (state->last_event == EVENT_EXIT) {
        printf("Exit code:          %d\n", state->exit_code);
    }
    printf("============================\n");
}