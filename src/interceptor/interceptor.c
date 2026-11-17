/*
 * BSDulator - Syscall Interceptor Implementation
 * Uses ptrace to intercept and translate FreeBSD syscalls
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/ptrace.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <grp.h>
#include "bsdulator.h"
#include "runtime/freebsd_runtime.h"
#include "bsdulator/jail.h"
#include "bsdulator/signal_emul.h"
#include "bsdulator/kqueue_emul.h"
#include "bsdulator/msg_emul.h"
#include "bsdulator/chain.h"
#include "bsdulator/thread_emul.h"
#include "bsdulator/seccomp.h"

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 310
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 311
#endif

#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL 0x100000
#endif
/* EXITKILL: if the tracer dies, the kernel kills every tracee, so no
 * FreeBSD program ever runs on without syscall translation */
#define PTRACE_OPTIONS (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | \
                        PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | \
                        PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL)

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
    
    /* Get network namespace name if configured */
    const char *netns = bsdulator_get_netns();

    /*
     * Container namespaces (lochs starts a holder process per container).
     * The PID namespace is joined by this tracer for its children only:
     * the traced program and everything it starts get container ids, while
     * the tracer keeps seeing host ids. Mount, UTS and IPC are joined in
     * the child below.
     */
    int ns_pid = bsdulator_get_ns_pid();
    int ns_fd[3] = { -1, -1, -1 };
    int user_fd = -1;
    int cap_last = 40;
    const char *run_binary = binary;
    char *const *run_argv = argv;
    static const char *ns_name[3] = { "mnt", "uts", "ipc" };
    static const int ns_type[3] = { CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC };
    if (ns_pid > 0) {
        char p[64];
        snprintf(p, sizeof(p), "/proc/%d/ns/pid", ns_pid);
        int pfd = open(p, O_RDONLY | O_CLOEXEC);
        if (pfd < 0 || setns(pfd, CLONE_NEWPID) < 0) {
            BSD_ERROR("cannot join the PID namespace of %d: %s", ns_pid, strerror(errno));
            if (pfd >= 0) close(pfd);
            return -1;
        }
        close(pfd);
        {
            char mine[64] = "", theirs[64] = "";
            snprintf(p, sizeof(p), "/proc/%d/ns/user", ns_pid);
            ssize_t a1 = readlink("/proc/self/ns/user", mine, sizeof(mine) - 1);
            ssize_t a2 = readlink(p, theirs, sizeof(theirs) - 1);
            if (a1 > 0 && a2 > 0) {
                mine[a1] = theirs[a2] = '\0';
                if (strcmp(mine, theirs) != 0) user_fd = open(p, O_RDONLY | O_CLOEXEC);
            }
        }
        for (int i = 0; i < 3; i++) {
            snprintf(p, sizeof(p), "/proc/%d/ns/%s", ns_pid, ns_name[i]);
            ns_fd[i] = open(p, O_RDONLY | O_CLOEXEC);
            if (ns_fd[i] < 0) {
                BSD_ERROR("cannot open %s: %s", p, strerror(errno));
                return -1;
            }
        }
        /* Read now: /proc is not mounted in the container */
        FILE *cf = fopen("/proc/sys/kernel/cap_last_cap", "r");
        if (cf) {
            if (fscanf(cf, "%d", &cap_last) != 1) cap_last = 40;
            fclose(cf);
        }
        /*
         * A container whose holder did pivot_root has the FreeBSD root as
         * its "/" and nothing of the host's filesystem. Its processes then
         * use FreeBSD paths unchanged, and the host paths lochs passes on
         * the command line are shortened to container paths.
         */
        const char *froot = bsdulator_get_freebsd_root();
        struct stat hs, rs, me;
        snprintf(p, sizeof(p), "/proc/%d/root/", ns_pid);
        if (froot && froot[0] && stat(p, &hs) == 0 && stat(froot, &rs) == 0 &&
            stat("/", &me) == 0 && hs.st_dev == rs.st_dev && hs.st_ino == rs.st_ino &&
            !(me.st_dev == rs.st_dev && me.st_ino == rs.st_ino)) {
            bsdulator_set_rooted(1);
            run_binary = jail_visible_path(binary);
            size_t n = 0;
            while (argv[n]) n++;
            char **na = calloc(n + 1, sizeof(char *));
            if (!na) return -1;
            for (size_t i = 0; i < n; i++) {
                const char *v = jail_visible_path(argv[i]);
                if (v == argv[i] && strncmp(argv[i], "path=", 5) == 0) {
                    const char *pv = jail_visible_path(argv[i] + 5);
                    if (pv != argv[i] + 5) {
                        char *t = malloc(strlen(pv) + 6);
                        if (t) {
                            sprintf(t, "path=%s", pv);
                            v = t;
                        }
                    }
                }
                na[i] = (char *)v;
            }
            run_argv = na;
            BSD_INFO("container root is pivoted: running %s", run_binary);
        }
    }
    
    pid_t pid = fork();
    
    if (pid < 0) {
        BSD_ERROR("fork() failed: %s", strerror(errno));
        return -1;
    }
    
    if (pid == 0) {
        /* Child process */
        
        /* Set up ptrace FIRST - this must happen before namespace switch */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace(TRACEME)");
            _exit(127);
        }
        
        /*
         * Order matters. The network namespace belongs to the host, so it
         * is joined while this process is still host root; then the
         * container's user namespace, then the namespaces it owns.
         */
        if (netns && netns[0]) {
            char netns_path[256];
            snprintf(netns_path, sizeof(netns_path), "/var/run/netns/%s", netns);
            int netns_fd = open(netns_path, O_RDONLY);
            if (netns_fd < 0) {
                fprintf(stderr, "Failed to open netns %s: %s\n", netns_path, strerror(errno));
                _exit(127);
            }
            if (setns(netns_fd, CLONE_NEWNET) < 0) {
                fprintf(stderr, "Failed to enter netns %s: %s\n", netns, strerror(errno));
                close(netns_fd);
                _exit(127);
            }
            close(netns_fd);
        }

        if (user_fd >= 0 && setns(user_fd, CLONE_NEWUSER) < 0) {
            fprintf(stderr, "Failed to enter user namespace: %s\n", strerror(errno));
            _exit(127);
        }

        /* Enter the container's mount, UTS and IPC namespaces */
        for (int i = 0; i < 3; i++) {
            if (ns_fd[i] >= 0 && setns(ns_fd[i], ns_type[i]) < 0) {
                fprintf(stderr, "Failed to enter %s namespace: %s\n", ns_name[i], strerror(errno));
                _exit(127);
            }
        }

        /* Become root of the container: host uid LOCHS_ID_BASE, not 0 */
        if (user_fd >= 0) {
            if (setgroups(0, NULL) < 0 || setresgid(0, 0, 0) < 0 || setresuid(0, 0, 0) < 0) {
                fprintf(stderr, "Failed to become container root: %s\n", strerror(errno));
                _exit(127);
            }
        }

        /*
         * Container processes keep only the capabilities Docker's default
         * profile keeps, and cannot gain privileges through exec. Root in
         * a container then cannot load modules, mount, trace other
         * processes, set the clock, or touch raw I/O on the host.
         */
        if (ns_pid > 0) {
            static const int keep[] = {
                0 /* CHOWN */, 1 /* DAC_OVERRIDE */, 3 /* FOWNER */, 4 /* FSETID */,
                5 /* KILL */, 6 /* SETGID */, 7 /* SETUID */, 8 /* SETPCAP */,
                10 /* NET_BIND_SERVICE */, 13 /* NET_RAW */, 18 /* SYS_CHROOT */,
                27 /* MKNOD */, 29 /* AUDIT_WRITE */, 31 /* SETFCAP */,
            };
            int last = cap_last;
            for (int c = 0; c <= last; c++) {
                int kept = 0;
                for (size_t k = 0; k < sizeof(keep) / sizeof(keep[0]); k++)
                    if (keep[k] == c) kept = 1;
                if (!kept && prctl(PR_CAPBSET_DROP, c, 0, 0, 0) < 0 && errno != EINVAL) {
                    fprintf(stderr, "Failed to drop capability %d: %s\n", c, strerror(errno));
                    _exit(127);
                }
            }
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
                fprintf(stderr, "Failed to set no_new_privs: %s\n", strerror(errno));
                _exit(127);
            }
            /* Syscalls that act on the whole host are refused */
            if (container_seccomp_install() < 0) {
                fprintf(stderr, "Failed to install the seccomp filter: %s\n", strerror(errno));
                _exit(127);
            }
        }
        
        raise(SIGSTOP);
        execve(run_binary, run_argv, envp);
        perror("execve");
        _exit(127);
    }

    for (int i = 0; i < 3; i++) if (ns_fd[i] >= 0) close(ns_fd[i]);
    if (user_fd >= 0) close(user_fd);
    
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
    if (jail_proc_own_root(pid)) {
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
 * Rewrite execve of a FreeBSD program to go through the FreeBSD dynamic
 * linker.
 *
 * bsdulator starts the first program as "ld-elf.so.1 <program>" and sets up
 * the FreeBSD process environment for that layout. Every FreeBSD program a
 * traced process starts later must be started the same way. In a jail the
 * process is chrooted into the container, so the linker is the jail's
 * /libexec/ld-elf.so.1; outside a jail it is <FreeBSD root>/libexec/
 * ld-elf.so.1. So, in a jail:
 *
 *   execve("/bin/ls", ["ls", "-l"], envp)
 * becomes
 *   execve("/libexec/ld-elf.so.1",
 *          ["/libexec/ld-elf.so.1", "-b", "/bin/ls", "--", "ls", "-l"], envp)
 *
 * "-b <exe>" makes rtld load <exe> and pass the next argument through as
 * argv[0], so the program sees its original argv unchanged.
 *
 * What is exec'd decides the rewrite (the file is read through
 * /proc/<pid>/root, so the path resolves inside the jail):
 *   - a dynamic ELF program: rewritten as above;
 *   - a "#!" script whose interpreter is a dynamic ELF program: rewritten
 *     to run the interpreter, with the kernel's argv rules
 *     ([interp, optional-arg, script, argv[1..]]);
 *   - a static ELF program (/rescue), or anything else: left alone, so
 *     the kernel runs it or fails with ENOEXEC and the shell falls back to
 *     running the file as a script itself.
 * Outside a jail only FreeBSD-branded ELF files (EI_OSABI 9) are
 * rewritten, so host Linux programs still run natively, and a script's
 * interpreter is looked up under the FreeBSD root.
 *
 * Returns 1 if execve was rewritten, 0 if no rewrite is needed, -1 on error
 * (the original execve then runs unchanged).
 */

#define JAILED_LDELF        "/libexec/ld-elf.so.1"
#define ELFOSABI_FREEBSD_   9
#define JAILED_MAX_ARGS     65536
#define JAILED_SCRATCH_MAX  (1024 * 1024)

/* struct open_how for openat2(2), defined here for older headers */
struct bsd_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};
#define BSD_RESOLVE_IN_ROOT 0x10
#ifndef SYS_openat2
#define SYS_openat2 437
#endif

/*
 * Open path as the jailed process would see it: absolute paths (and
 * absolute symlinks) resolve inside its root, relative ones from its cwd.
 */
static int open_in_process(pid_t pid, const char *path) {
    char dir[64];
    snprintf(dir, sizeof(dir), "/proc/%d/%s", (int)pid,
             path[0] == '/' ? "root" : "cwd");
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return -1;

    int fd = -1;
    if (path[0] == '/') {
        struct bsd_open_how how = {
            .flags = O_RDONLY | O_CLOEXEC,
            .mode = 0,
            .resolve = BSD_RESOLVE_IN_ROOT,
        };
        fd = (int)syscall(SYS_openat2, dfd, path, &how, sizeof(how));
        if (fd < 0 && errno == ENOSYS) {
            /* Kernels before 5.6: absolute symlinks would escape, but
             * plain paths still resolve correctly. */
            fd = openat(dfd, path + 1, O_RDONLY | O_CLOEXEC);
        }
    } else {
        fd = openat(dfd, path, O_RDONLY | O_CLOEXEC);
    }
    close(dfd);
    return fd;
}

typedef enum {
    EXEC_OTHER,        /* not something we rewrite */
    EXEC_ELF_DYNAMIC,  /* ELF with a PT_INTERP: needs ld-elf */
    EXEC_ELF_STATIC,   /* ELF without PT_INTERP */
    EXEC_SCRIPT,       /* "#!" line; interpreter in *interp, arg in *iarg */
} exec_kind_t;

/* Classify an exec target; for scripts, parse the "#!" line. */
static exec_kind_t classify_exec(pid_t pid, const char *path,
                                 char *interp, size_t interp_sz,
                                 char *iarg, size_t iarg_sz, int *osabi) {
    *osabi = -1;
    int fd = open_in_process(pid, path);
    if (fd < 0) return EXEC_OTHER;

    /* Only rewrite what the kernel would run: a regular file with an
     * execute bit. Anything else is left to the original execve, which
     * fails with the right error (EACCES, ENOEXEC). Without this, running
     * a script through its interpreter would skip the permission check. */
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
        !(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
        close(fd);
        return EXEC_OTHER;
    }

    unsigned char buf[256];
    ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
    if (n < 4) {
        close(fd);
        return EXEC_OTHER;
    }

    if (n >= 2 && buf[0] == '#' && buf[1] == '!') {
        close(fd);
        buf[n] = '\0';
        char *p = (char *)buf + 2;
        char *eol = strchr(p, '\n');
        if (eol) *eol = '\0';
        while (*p == ' ' || *p == '\t') p++;
        char *end = p;
        while (*end && *end != ' ' && *end != '\t') end++;
        size_t ilen = (size_t)(end - p);
        if (ilen == 0 || ilen >= interp_sz) return EXEC_OTHER;
        memcpy(interp, p, ilen);
        interp[ilen] = '\0';
        /* Like the kernel: the rest of the line is one optional argument,
         * with surrounding blanks removed. */
        p = end;
        while (*p == ' ' || *p == '\t') p++;
        size_t alen = strlen(p);
        while (alen > 0 && (p[alen - 1] == ' ' || p[alen - 1] == '\t' ||
                            p[alen - 1] == '\r'))
            alen--;
        if (alen >= iarg_sz) alen = iarg_sz - 1;
        memcpy(iarg, p, alen);
        iarg[alen] = '\0';
        return EXEC_SCRIPT;
    }

    if (memcmp(buf, "\177ELF", 4) != 0 || n < 64 || buf[4] != 2 /* 64-bit */) {
        close(fd);
        return EXEC_OTHER;
    }

    *osabi = buf[7];  /* EI_OSABI: 9 = FreeBSD */
    uint64_t phoff;
    uint16_t phentsize, phnum;
    memcpy(&phoff, buf + 32, sizeof(phoff));
    memcpy(&phentsize, buf + 54, sizeof(phentsize));
    memcpy(&phnum, buf + 56, sizeof(phnum));

    exec_kind_t kind = EXEC_ELF_STATIC;
    for (uint16_t i = 0; i < phnum && phentsize >= 4; i++) {
        uint32_t p_type;
        if (pread(fd, &p_type, sizeof(p_type),
                  (off_t)(phoff + (uint64_t)i * phentsize)) != sizeof(p_type))
            break;
        if (p_type == 3 /* PT_INTERP */) {
            kind = EXEC_ELF_DYNAMIC;
            break;
        }
    }
    close(fd);
    return kind;
}

/* Append a string to the scratch buffer; returns its offset or -1. */
static long scratch_add(char *scratch, size_t *used, const char *s) {
    size_t len = strlen(s) + 1;
    if (*used + len > JAILED_SCRATCH_MAX) return -1;
    memcpy(scratch + *used, s, len);
    long off = (long)*used;
    *used += len;
    return off;
}

static int rewrite_freebsd_execve(pid_t pid, uint64_t *args) {
    int jid = jail_get_process_jid(pid);

    /* The FreeBSD root as this process sees it: "" in a jail (chrooted) or
     * a pivoted container, else the -r root on the host. */
    char root[1024] = "";
    if (!jail_proc_own_root(pid)) {
        const char *r = bsdulator_get_freebsd_root();
        if (!r || !r[0]) return 0;
        /* Absolute, so it still works after the program changes directory */
        char abs_root[PATH_MAX];
        if (realpath(r, abs_root)) r = abs_root;
        size_t rl = strlen(r);
        while (rl > 1 && r[rl - 1] == '/') rl--;
        if (rl >= sizeof(root)) return 0;
        memcpy(root, r, rl);
        root[rl] = '\0';
    }
    char ldelf[sizeof(root) + sizeof(JAILED_LDELF)];
    snprintf(ldelf, sizeof(ldelf), "%s%s", root, JAILED_LDELF);

    char path_buf[1024];
    ssize_t path_len = interceptor_read_string(pid, path_buf, (const void *)args[0], sizeof(path_buf));
    if (path_len <= 0) {
        BSD_WARN("rewrite_freebsd_execve: failed to read path");
        return -1;
    }

    BSD_INFO("rewrite_freebsd_execve: process %d (jid=%d) exec'ing '%s'", (int)pid, jid, path_buf);

    if (strstr(path_buf, "ld-elf.so") != NULL) {
        BSD_TRACE("rewrite_freebsd_execve: already ld-elf, skipping");
        return 0;
    }

    /*
     * Outside a jail, an absolute path names a file in the FreeBSD root
     * when it exists there. Path translation skips paths that also exist
     * on the host, so without this "/usr/bin/cat" from a FreeBSD shell
     * would run the host's Linux cat under the FreeBSD syscall layer.
     */
    if (root[0] && path_buf[0] == '/' &&
        strncmp(path_buf, root, strlen(root)) != 0) {
        char cand[sizeof(root) + sizeof(path_buf)];
        snprintf(cand, sizeof(cand), "%s%s", root, path_buf);
        int cfd = open_in_process(pid, cand);
        if (cfd >= 0) {
            close(cfd);
            if (strlen(cand) >= sizeof(path_buf)) return -1;
            snprintf(path_buf, sizeof(path_buf), "%s", cand);
            path_len = (ssize_t)strlen(path_buf);
        }
    }

    char interp[1280] = "", iarg[256] = "";
    int osabi = -1;
    exec_kind_t kind = classify_exec(pid, path_buf, interp, 256,
                                     iarg, sizeof(iarg), &osabi);
    if (kind == EXEC_SCRIPT) {
        /* Outside a jail, "#!/bin/sh" means the FreeBSD root's /bin/sh */
        if (root[0] && interp[0] == '/' &&
            strncmp(interp, root, strlen(root)) != 0) {
            char full[sizeof(interp)];
            snprintf(full, sizeof(full), "%s%s", root, interp);
            snprintf(interp, sizeof(interp), "%s", full);
        }
        char unused1[8], unused2[8];
        int iosabi = -1;
        exec_kind_t ik = classify_exec(pid, interp, unused1, sizeof(unused1),
                                       unused2, sizeof(unused2), &iosabi);
        if (ik != EXEC_ELF_DYNAMIC || (root[0] && iosabi != ELFOSABI_FREEBSD_)) {
            BSD_TRACE("rewrite_freebsd_execve: script interpreter '%s' is not a dynamic ELF, leaving to kernel", interp);
            return 0;
        }
    } else if (kind != EXEC_ELF_DYNAMIC || (root[0] && osabi != ELFOSABI_FREEBSD_)) {
        BSD_TRACE("rewrite_freebsd_execve: '%s' is not a dynamic ELF, leaving to kernel", path_buf);
        return 0;
    }

    /* Count the original argv */
    uint64_t orig_argv = args[1];
    size_t orig_argc = 0;
    while (orig_argv && orig_argc < JAILED_MAX_ARGS) {
        errno = 0;
        long p = ptrace(PTRACE_PEEKDATA, pid, (void *)(orig_argv + orig_argc * 8), NULL);
        if (errno != 0) {
            BSD_WARN("rewrite_freebsd_execve: failed to read argv[%zu]", orig_argc);
            return -1;
        }
        if (p == 0) break;
        orig_argc++;
    }
    if (orig_argc >= JAILED_MAX_ARGS) {
        BSD_WARN("rewrite_freebsd_execve: too many arguments");
        return -1;
    }

    /*
     * Build the new strings and argv in one local buffer, then copy it
     * below the child's stack pointer (the address space is replaced by
     * the exec, so that memory is free to use).
     *   ld-elf -b <exe> -- <argv0> [script args] argv[1..] NULL
     */
    char *scratch = malloc(JAILED_SCRATCH_MAX);
    if (!scratch) return -1;
    size_t used = 0;
    long off_ldelf = scratch_add(scratch, &used, ldelf);
    long off_b = scratch_add(scratch, &used, "-b");
    long off_dash = scratch_add(scratch, &used, "--");
    long off_path = scratch_add(scratch, &used, path_buf);
    long off_interp = -1, off_iarg = -1;
    if (kind == EXEC_SCRIPT) {
        off_interp = scratch_add(scratch, &used, interp);
        if (iarg[0]) off_iarg = scratch_add(scratch, &used, iarg);
    }
    if (off_ldelf < 0 || off_b < 0 || off_dash < 0 || off_path < 0 ||
        (kind == EXEC_SCRIPT && off_interp < 0) ||
        (iarg[0] && kind == EXEC_SCRIPT && off_iarg < 0)) {
        free(scratch);
        return -1;
    }
    used = (used + 7) & ~(size_t)7;

    size_t new_argc = 3 /* ld-elf -b exe */ + 1 /* -- */ + 1 /* argv0 */ +
                      (kind == EXEC_SCRIPT ? (off_iarg >= 0 ? 2 : 1) : 0) +
                      (orig_argc > 0 ? orig_argc - 1 : 0) + 1 /* NULL */;
    size_t argv_bytes = new_argc * 8;
    if (used + argv_bytes > JAILED_SCRATCH_MAX) {
        free(scratch);
        return -1;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        BSD_ERROR("rewrite_freebsd_execve: failed to get regs");
        free(scratch);
        return -1;
    }
    size_t total = used + argv_bytes;
    uint64_t base = (regs.rsp - 4096 - total) & ~0xFULL;

    uint64_t *nargv = (uint64_t *)(scratch + used);
    size_t k = 0;
    nargv[k++] = base + (uint64_t)off_ldelf;
    nargv[k++] = base + (uint64_t)off_b;
    if (kind == EXEC_SCRIPT) {
        /* Load the interpreter; it sees [interp, arg?, script, argv[1..]] */
        nargv[k++] = base + (uint64_t)off_interp;
        nargv[k++] = base + (uint64_t)off_dash;
        nargv[k++] = base + (uint64_t)off_interp;
        if (off_iarg >= 0) nargv[k++] = base + (uint64_t)off_iarg;
        nargv[k++] = base + (uint64_t)off_path;
    } else {
        /* Load the program; it sees its original argv[0] */
        nargv[k++] = base + (uint64_t)off_path;
        nargv[k++] = base + (uint64_t)off_dash;
        if (orig_argc > 0) {
            errno = 0;
            long a0 = ptrace(PTRACE_PEEKDATA, pid, (void *)orig_argv, NULL);
            nargv[k++] = errno == 0 ? (uint64_t)a0 : base + (uint64_t)off_path;
        } else {
            nargv[k++] = base + (uint64_t)off_path;
        }
    }
    for (size_t i = 1; i < orig_argc; i++) {
        errno = 0;
        long a = ptrace(PTRACE_PEEKDATA, pid, (void *)(orig_argv + i * 8), NULL);
        if (errno != 0) {
            free(scratch);
            return -1;
        }
        nargv[k++] = (uint64_t)a;
    }
    nargv[k++] = 0;

    if (interceptor_write_mem(pid, scratch, (void *)base, used + k * 8) < 0) {
        BSD_ERROR("rewrite_freebsd_execve: failed to write new argv");
        free(scratch);
        return -1;
    }
    free(scratch);

    args[0] = base + (uint64_t)off_ldelf;  /* path = /libexec/ld-elf.so.1 */
    args[1] = base + used;                 /* argv = [ld-elf, -b, exe, --, ...] */
    /* args[2] (envp) stays the same */

    if (kind == EXEC_SCRIPT)
        BSD_INFO("rewrite_freebsd_execve: script '%s' -> %s -b %s", path_buf, ldelf, interp);
    else
        BSD_INFO("rewrite_freebsd_execve: rewrote to: %s -b %s", ldelf, path_buf);
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
    if (jail_proc_own_root(pid)) {
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

    /* Already inside the FreeBSD root (e.g. the -r path itself) */
    {
        size_t rl = strlen(freebsd_root);
        while (rl > 1 && freebsd_root[rl - 1] == '/') rl--;
        if (strncmp(path_buf, freebsd_root, rl) == 0 &&
            (path_buf[rl] == '/' || path_buf[rl] == '\0')) {
            return -1;
        }
    }

    /* Check if it's a path we should translate */
    int should_translate = 0;
    if (strncmp(path_buf, "/libexec/", 9) == 0 ||
        strncmp(path_buf, "/lib/", 5) == 0 ||
        strncmp(path_buf, "/usr/lib/", 9) == 0 ||
        strncmp(path_buf, "/usr/libexec/", 13) == 0 ||
        strncmp(path_buf, "/usr/share/", 11) == 0 ||
        strncmp(path_buf, "/etc/", 5) == 0 ||
        strncmp(path_buf, "/bin/", 5) == 0 ||
        strncmp(path_buf, "/sbin/", 6) == 0 ||
        strncmp(path_buf, "/usr/bin/", 9) == 0 ||
        strncmp(path_buf, "/usr/sbin/", 10) == 0 ||
        strncmp(path_buf, "/rescue/", 8) == 0 ||
        strncmp(path_buf, "/tmp/", 5) == 0) {
        should_translate = 1;
    }
    /* Note: /var/ removed from translation list - it often exists on real filesystem */

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

    /*
     * A FreeBSD program means the FreeBSD root's file. Fall back to the
     * host's file only when the root has none and the host does (say,
     * /etc/resolv.conf). Checking the host first made a FreeBSD shell
     * searching PATH find host Linux programs such as /usr/bin/cat.
     */
    /* Program and library directories always mean the FreeBSD root: a
     * host Linux binary or library cannot run under the FreeBSD layer. */
    int host_fallback = strncmp(path_buf, "/etc/", 5) == 0 ||
                        strncmp(path_buf, "/usr/share/", 11) == 0 ||
                        strncmp(path_buf, "/tmp/", 5) == 0;
    if (host_fallback && access(new_path, F_OK) != 0 && access(path_buf, F_OK) == 0) {
        BSD_TRACE("Path '%s' is not in the FreeBSD root but exists on the host; using the host's", path_buf);
        return -1;
    }

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
    /* The syscall this process is inside (saved at entry, used at exit) */
    int sc_valid;
    uint64_t sc_raw_args[6];  /* arguments as the program passed them */
    int first_stop;           /* next stop is the new child's initial one */
    int initial_sigstop_due;  /* its initial SIGSTOP is still to come */
    uint64_t sc_nr;
    uint64_t sc_args[6];
    size_t mmap_alignment;
    size_t mmap_orig_size;
    uint64_t mmap_alloc_size;
} process_entry_t;

static process_entry_t process_table[512];
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
    /* Reuse the slot of an exited process, so long-running jails that
     * start many processes (shell loops, forking servers) never run out. */
    for (int i = 0; i < process_count; i++) {
        if (!process_table[i].active) {
            entry = &process_table[i];
            break;
        }
    }
    if (!entry && process_count < 512) {
        entry = &process_table[process_count++];
    }
    if (entry) {
        entry->pid = pid;
        entry->active = 1;
        entry->in_syscall = 0;
        entry->skip_post_exec = 0;
        entry->sc_valid = 0;
        entry->first_stop = 1;
        entry->initial_sigstop_due = 0;
        BSD_TRACE("Added process %d to table (count=%d)", pid, process_count);
        return entry;
    }
    return NULL;
}

/*
 * The process a new task belongs to: its thread-group leader for a thread,
 * else its parent (both from /proc/<pid>/status). Returns 0 if unknown.
 */
static pid_t parent_of(pid_t pid) {
    char path[64], line[128];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    pid_t tgid = 0, ppid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Tgid:", 5) == 0) tgid = (pid_t)atoi(line + 5);
        else if (strncmp(line, "PPid:", 5) == 0) ppid = (pid_t)atoi(line + 5);
    }
    fclose(f);
    if (tgid > 0 && tgid != pid) return tgid;
    return ppid;
}

/* Mark a process as exited */
static void remove_process(pid_t pid) {
    process_entry_t *entry = find_process(pid);
    if (entry) {
        entry->active = 0;
        BSD_TRACE("Marked process %d as exited", pid);
    }
    /* Forget its jail membership too: the PID can be reused later by a
     * process that is not in the jail. */
    jail_forget_process(pid);
    sig_proc_exit(pid);
    kq_proc_exit(pid);
    chain_proc_exit(pid);
    freebsd_exe_path_forget(pid);
}

/* Count active processes */
static int count_active_processes(void) {
    int count = 0;
    for (int i = 0; i < process_count; i++) {
        if (process_table[i].active) count++;
    }
    return count;
}

static int main_exited = 0, main_exit_code = 0;
static void (*main_exit_hook)(int) = NULL;

void interceptor_set_main_exit_hook(void (*hook)(int exit_code)) {
    main_exit_hook = hook;
}

/*
 * The first traced process has exited with code. Returns 1 when tracing
 * is over, 0 when others are still running and tracing goes on.
 */
static int on_main_exit(interceptor_state_t *state, int code) {
    main_exited = 1;
    main_exit_code = code;
    state->exit_code = code;
    int active = count_active_processes();
    if (active == 0) {
        state->running = false;
        state->last_event = EVENT_EXIT;
        return 1;
    }
    BSD_INFO("Main process exited (%d); still tracing %d processes", code, active);
    if (main_exit_hook) main_exit_hook(code);
    state->last_event = EVENT_NONE;
    return 0;
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
    
    result = waitpid(-1, &status, __WALL);
    
    /* Update pid to the process that actually stopped */
    if (result > 0) {
        state->pid = result;
        
        /* Auto-add to process table if not already there */
        if (!find_process(result)) {
            add_process(result);
            /* A new child can stop before its parent's fork event is
             * seen; take its jail from the parent now. */
            pid_t parent = parent_of(result);
            if (parent > 0) {
                jail_inherit_process(parent, result);
                sig_proc_fork(parent, result);
            }
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
            if (main_exited) state->exit_code = main_exit_code;
            return 0;
        }
        BSD_ERROR("waitpid() failed: %s", strerror(errno));
        return -1;
    }
    
    if (WIFEXITED(status)) {
        BSD_INFO("Process %d exited with code %d", state->pid, WEXITSTATUS(status));
        
        /* Mark this process as exited in our table */
        remove_process(state->pid);
        
        if (state->pid == main_pid && !main_exited) {
            /* Processes it started keep being traced until they exit */
            on_main_exit(state, WEXITSTATUS(status));
            return 0;
        }
        
        /* A child exited - check if there are other active processes */
        int active = count_active_processes();
        BSD_INFO("Child %d exited, %d active processes remaining", state->pid, active);
        
        if (active == 0) {
            /* No more processes - we're done */
            state->running = false;
            state->last_event = EVENT_EXIT;
            state->exit_code = main_exited ? main_exit_code : 0;
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
        
        if (state->pid == main_pid && !main_exited) {
            on_main_exit(state, 128 + WTERMSIG(status));
            return 0;
        }
        
        /* A child was killed - check remaining processes */
        int active = count_active_processes();
        BSD_INFO("Child %d killed, %d active processes remaining", state->pid, active);
        
        if (active == 0) {
            state->running = false;
            state->last_event = EVENT_EXIT;
            state->exit_code = main_exited ? main_exit_code : 128 + WTERMSIG(status);
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
            {
                process_entry_t *fe = find_process(state->pid);
                if (fe) fe->first_stop = 0;
            }
            
            if (get_in_syscall(state->pid)) {
                state->last_event = EVENT_SYSCALL_ENTER;
                state->syscall_nr = regs.orig_rax;
                state->args[0] = regs.rdi;
                state->args[1] = regs.rsi;
                state->args[2] = regs.rdx;
                state->args[3] = regs.r10;
                state->args[4] = regs.r8;
                state->args[5] = regs.r9;
                process_entry_t *pe = find_process(state->pid);
                if (pe) memcpy(pe->sc_raw_args, state->args, sizeof(pe->sc_raw_args));
            } else {
                state->last_event = EVENT_SYSCALL_EXIT;
                state->retval = (int64_t)regs.rax;
                /*
                 * FreeBSD reports success with the carry flag clear and
                 * libc tests it (jb cerror). Linux returns with the flags
                 * the program had before the syscall, so a stale CF made
                 * successful syscalls look like failures with errno 0.
                 * Clear it after a real syscall that succeeded. Emulated
                 * syscalls (orig_rax == -1) set CF themselves.
                 */
                if ((int64_t)regs.orig_rax != -1 && (regs.eflags & 0x1) &&
                    !((int64_t)regs.rax < 0 && (int64_t)regs.rax > -4096)) {
                    regs.eflags &= ~0x1ULL;
                    (void)ptrace(PTRACE_SETREGS, state->pid, NULL, &regs);
                }
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
                    jail_inherit_process(state->pid, (pid_t)child_pid);
                    sig_proc_fork(state->pid, (pid_t)child_pid);
                    freebsd_exe_path_inherit(state->pid, (pid_t)child_pid);
                    
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
                    jail_inherit_process(state->pid, (pid_t)child_pid);
                    sig_proc_fork(state->pid, (pid_t)child_pid);
                    freebsd_exe_path_inherit(state->pid, (pid_t)child_pid);
                    
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
                    jail_inherit_process(state->pid, (pid_t)clone_child_pid);
                    if (thr_tgid((pid_t)clone_child_pid) == thr_tgid(state->pid))
                        sig_thread_create(state->pid, (pid_t)clone_child_pid);
                    else
                        sig_proc_fork(state->pid, (pid_t)clone_child_pid);
                    thr_on_clone(state->pid, (pid_t)clone_child_pid);
                    freebsd_exe_path_inherit(state->pid, (pid_t)clone_child_pid);
                    
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
                    sig_proc_exec(state->pid);
                    kq_proc_exec(state->pid);
                    
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

        process_entry_t *se = find_process(state->pid);
        int first = se && se->first_stop;
        if (se) se->first_stop = 0;
        if (first) {
            /* A new task's first stop. Set it up (a thr_new thread is
             * pointed at its start function) whatever stopped it: a signal
             * sent right after creation, such as pthread_kill(), has a
             * lower number than the initial SIGSTOP and arrives first. */
            if (!thr_on_first_stop(state->pid))
                (void)thr_rfork_child_first_stop(state->pid);
            if (sig != SIGSTOP && se) se->initial_sigstop_due = 1;
        }
        if (sig == SIGSTOP && (first || (se && se->initial_sigstop_due))) {
            /* The initial stop under PTRACE_O_TRACEFORK: not delivered */
            if (se) se->initial_sigstop_due = 0;
            state->last_event = EVENT_NONE;
            return 0;
        }
        siginfo_t gsi;
        memset(&gsi, 0, sizeof(gsi));
        if (ptrace(PTRACE_GETSIGINFO, state->pid, NULL, &gsi) < 0 && errno == EINVAL) {
            /* Group-stop (job control), not a signal to deliver */
            state->last_event = EVENT_NONE;
            return 0;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, state->pid, NULL, &regs) == 0 &&
            regs.rip != SIG_RETURN_MAGIC) {
            BSD_TRACE("Signal %d at RIP=0x%llx RSP=0x%llx",
                    sig, (unsigned long long)regs.rip,
                    (unsigned long long)regs.rsp);
            /* Only real faults (si_code > 0), not a kill(SIGSEGV) */
            if ((sig == SIGSEGV || sig == SIGBUS) && gsi.si_code > 0) {
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
 * Several traced processes can be inside syscalls at once (a pipeline, a
 * forking server), and their stops arrive interleaved. state->syscall_nr,
 * state->args and the pending mmap fixup describe the last syscall ENTRY
 * seen, of whichever process. Save them per process at entry and restore
 * them at that process's exit, so exit handling (stat translation, mmap
 * alignment, return translation) uses the right syscall.
 */
static void save_syscall_state(const interceptor_state_t *state) {
    process_entry_t *e = find_process(state->pid);
    if (!e) return;
    e->sc_valid = 1;
    e->sc_nr = state->syscall_nr;
    memcpy(e->sc_args, state->args, sizeof(e->sc_args));
    e->mmap_alignment = pending_mmap_alignment;
    e->mmap_orig_size = pending_mmap_orig_size;
    e->mmap_alloc_size = pending_mmap_alloc_size;
}

static void restore_syscall_state(interceptor_state_t *state) {
    process_entry_t *e = find_process(state->pid);
    if (!e || !e->sc_valid) return;
    state->syscall_nr = e->sc_nr;
    memcpy(state->args, e->sc_args, sizeof(e->sc_args));
    pending_mmap_alignment = e->mmap_alignment;
    pending_mmap_orig_size = e->mmap_orig_size;
    pending_mmap_alloc_size = e->mmap_alloc_size;
    e->sc_valid = 0;
}

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

/*
 * Convert a socket address the kernel wrote (Linux layout: 16-bit family)
 * to FreeBSD's (8-bit sa_len, 8-bit family; AF_INET6 is 28, not 10).
 */
static void sockaddr_out_to_freebsd(pid_t pid, uint64_t addr_ptr, uint64_t len_ptr) {
    if (!addr_ptr || !len_ptr) return;
    uint32_t len = 0;
    if (interceptor_read_mem(pid, &len, (const void *)len_ptr, sizeof(len)) != sizeof(len) || len < 2)
        return;
    uint8_t a[128];
    if (len > sizeof(a)) len = sizeof(a);
    if (interceptor_read_mem(pid, a, (const void *)addr_ptr, len) != (ssize_t)len) return;
    uint16_t fam;
    memcpy(&fam, a, 2);
    uint8_t f = fam == 10 ? 28 : (uint8_t)fam;  /* AF_INET6 */
    a[0] = (uint8_t)len;
    a[1] = f;
    (void)interceptor_write_mem(pid, a, (void *)addr_ptr, len);
}

/* Main interception loop */
int interceptor_run(interceptor_state_t *state) {
    /* Initialize process table */
    memset(process_table, 0, sizeof(process_table));
    process_count = 0;
    
    main_pid = state->pid;  /* Set global main_pid */
    main_exited = 0;
    main_exit_code = 0;
    add_process(main_pid);  /* Add main process to table */
    {
        process_entry_t *me = find_process(main_pid);
        if (me) me->first_stop = 0;  /* its initial stop was consumed at spawn */
    }
    sig_proc_start(main_pid);
    
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

                if (chain_busy(state->pid)) {
                    /* A step of a syscall chain: already Linux */
                    save_syscall_state(state);
                    break;
                }
                if (kq_on_syscall_entry(state->pid)) {
                    /* A step of a kevent/kqueue chain: already Linux */
                    save_syscall_state(state);
                    break;
                }
                if (sig_on_syscall_entry(state->pid, state->syscall_nr)) {
                    /* The kernel resuming an interrupted sleep
                     * (restart_syscall): a Linux syscall, run it as is. */
                    save_syscall_state(state);
                    break;
                }

                int linux_nr;
                syscall_result_t result = syscall_translate((int)state->syscall_nr, &linux_nr);
                
                const char *name = syscall_name((int)state->syscall_nr);
                BSD_WARN("ENTER FreeBSD syscall %llu (%s) -> Linux %d",
                (unsigned long long)state->syscall_nr,
                name ? name : "unknown",
                linux_nr);

                /* Debug logging for socket syscall to diagnose DNS issues */
                if ((int)state->syscall_nr == FBSD_SYS_socket) {
                    BSD_INFO("==> socket: domain=%llu type=%llu protocol=%llu",
                             (unsigned long long)state->args[0],
                             (unsigned long long)state->args[1],
                             (unsigned long long)state->args[2]);
                }

                /* Debug logging for recvfrom to diagnose DNS issues */
                if ((int)state->syscall_nr == FBSD_SYS_recvfrom) {
                    BSD_INFO("==> recvfrom: fd=%llu buf=0x%llx len=%llu flags=0x%llx addr=0x%llx addrlen=0x%llx",
                             (unsigned long long)state->args[0],
                             (unsigned long long)state->args[1],
                             (unsigned long long)state->args[2],
                             (unsigned long long)state->args[3],
                             (unsigned long long)state->args[4],
                             (unsigned long long)state->args[5]);
                }

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
                 * Start FreeBSD programs through ld-elf.so.1, the way the
                 * first program was started (see rewrite_freebsd_execve).
                 */
                if ((int)state->syscall_nr == FBSD_SYS_execve) {
                    int rewritten = rewrite_freebsd_execve(state->pid, state->args);
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
                            /* Special: emulator modified child's memory, now execute syscall normally.
                             * We MUST translate the syscall number to Linux since emulated syscalls
                             * don't have a linux_nr in the table! */
                            BSD_INFO("Emulated syscall modified memory, translating and executing");
                            
                            /* Map FreeBSD socket syscall numbers to Linux equivalents */
                            int actual_linux_nr = -1;
                            switch ((int)state->syscall_nr) {
                                case FBSD_SYS_socket:     actual_linux_nr = 41; break;  /* SYS_socket */
                                case FBSD_SYS_connect:    actual_linux_nr = 42; break;  /* SYS_connect */
                                case FBSD_SYS_bind:       actual_linux_nr = 49; break;  /* SYS_bind */
                                case FBSD_SYS_sendto:     actual_linux_nr = 44; break;  /* SYS_sendto */
                                case FBSD_SYS_setsockopt: actual_linux_nr = 54; break;  /* SYS_setsockopt */
                                case FBSD_SYS_getsockopt: actual_linux_nr = 55; break;  /* SYS_getsockopt */
                                case FBSD_SYS_jail_attach: actual_linux_nr = 161; break;  /* SYS_chroot - jail_attach rewrites to chroot */
                                case FBSD_SYS_sigsuspend:  actual_linux_nr = SYS_rt_sigsuspend; break;
                                case FBSD_SYS_procctl:     actual_linux_nr = SYS_prctl; break;
                                case FBSD_SYS_wait6:       actual_linux_nr = SYS_wait4; break;
                                case FBSD_SYS_ioctl:       actual_linux_nr = SYS_ioctl; break;
                                case FBSD_SYS_fcntl:       actual_linux_nr = SYS_fcntl; break;
                                case FBSD_SYS_sendmsg:     actual_linux_nr = SYS_sendmsg; break;
                                case FBSD_SYS_recvmsg:     actual_linux_nr = SYS_recvmsg; break;
                                case 0:                    /* indirect syscall: handler set it */
                                case FBSD_SYS_kqueue:
                                case FBSD_SYS_kqueuex:
                                case FBSD_SYS_kevent:
                                case FBSD_SYS__umtx_op:
                                case FBSD_SYS_thr_exit:    actual_linux_nr = -2; break;  /* handler set it */
                                case FBSD_SYS_thr_new:
                                case FBSD_SYS_rfork:       actual_linux_nr = SYS_clone; break;
                                case FBSD_SYS_sigwait:
                                case FBSD_SYS_sigtimedwait:
                                case FBSD_SYS_sigwaitinfo: actual_linux_nr = SYS_rt_sigtimedwait; break;
                                default:
                                    actual_linux_nr = -1;
                                    BSD_ERROR("No Linux syscall mapping for emulated FreeBSD syscall %d",
                                              (int)state->syscall_nr);
                                    break;
                            }
                            
                            /* For setsockopt/getsockopt/socket, also update the args (translated) */
                            if ((int)state->syscall_nr == FBSD_SYS_setsockopt ||
                                (int)state->syscall_nr == FBSD_SYS_getsockopt ||
                                (int)state->syscall_nr == FBSD_SYS_socket ||
                                (int)state->syscall_nr == FBSD_SYS_thr_new ||
                                (int)state->syscall_nr == FBSD_SYS_rfork ||
                                (int)state->syscall_nr == FBSD_SYS_sendmsg ||
                                (int)state->syscall_nr == FBSD_SYS_recvmsg ||
                                (int)state->syscall_nr == FBSD_SYS_bind ||
                                (int)state->syscall_nr == FBSD_SYS_connect ||
                                (int)state->syscall_nr == FBSD_SYS_sendto ||
                                (int)state->syscall_nr == FBSD_SYS_procctl ||
                                (int)state->syscall_nr == FBSD_SYS_wait6 ||
                                (int)state->syscall_nr == FBSD_SYS_ioctl ||
                                (int)state->syscall_nr == FBSD_SYS_fcntl ||
                                (int)state->syscall_nr == FBSD_SYS_sigsuspend ||
                                (int)state->syscall_nr == FBSD_SYS_sigwait ||
                                (int)state->syscall_nr == FBSD_SYS_sigtimedwait ||
                                (int)state->syscall_nr == FBSD_SYS_sigwaitinfo) {
                                if (interceptor_set_args(state->pid, state->args) < 0) {
                                    BSD_ERROR("Failed to update args for sockopt syscall");
                                }
                            }
                            
                            if (actual_linux_nr >= 0) {
                                BSD_TRACE("  Translating emulated syscall %llu -> %d",
                                          (unsigned long long)state->syscall_nr, actual_linux_nr);
                                if (interceptor_set_syscall(state->pid, (uint64_t)actual_linux_nr) < 0) {
                                    BSD_ERROR("Failed to set syscall number for emulated syscall");
                                }
                            }
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
                save_syscall_state(state);
                break;
            }

            case EVENT_SYSCALL_EXIT: {
                /* Another process may have entered a syscall since this
                 * one did: handle the exit with this process's own syscall
                 * number, arguments and pending mmap fixup. */
                restore_syscall_state(state);
                {
                    int cr = chain_on_exit(state->pid);
                    if (cr) {
                        if (cr == 2) sig_after_syscall(state->pid, state->syscall_nr, state->args);
                        break;
                    }
                }
                {
                    /* kevent/kqueue chains run several Linux syscalls */
                    int kr = kq_on_syscall_exit(state->pid);
                    if (kr) {
                        if (kr == 2) sig_after_syscall(state->pid, FBSD_SYS_kevent, state->args);
                        break;
                    }
                }
                BSD_TRACE("EXIT syscall %llu = %lld (0x%llx)",
                          (unsigned long long)state->syscall_nr,
                          (long long)state->retval,
                          (unsigned long long)state->retval);
                
                /* Monitor __stack_chk_guard for changes */
                /* Skip stack_chk_guard monitoring for jailed processes - 
                 * the hardcoded address doesn't apply inside jails */
                if (jail_get_process_jid(state->pid) <= 0) {
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
                 * recvfrom sockaddr translation (Linux -> FreeBSD)
                 * Linux sockaddr_in: sa_family (2 bytes), sa_data...
                 * FreeBSD sockaddr_in: sin_len (1 byte), sin_family (1 byte), sa_data...
                 * We need to shift bytes to add the length prefix.
                 */
                /* Socket addresses the kernel returned: Linux layout to
                 * FreeBSD (sa_len byte, family numbers) */
                if (state->retval >= 0) {
                    switch ((int)state->syscall_nr) {
                        case FBSD_SYS_recvfrom:
                            sockaddr_out_to_freebsd(state->pid, state->args[4], state->args[5]);
                            break;
                        case FBSD_SYS_accept:
                        case FBSD_SYS_accept4:
                        case FBSD_SYS_getsockname:
                        case FBSD_SYS_getpeername:
                            sockaddr_out_to_freebsd(state->pid, state->args[1], state->args[2]);
                            break;
                        default:
                            break;
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

                /*
                 * A syscall interrupted by a signal returns one of the
                 * kernel-internal ERESTART* codes. The kernel restarts it
                 * (or turns it into EINTR) after the signal, using
                 * orig_rax, which holds the Linux number we substituted at
                 * entry; the restart would then be read as a FreeBSD
                 * syscall number. Leave the code alone and put the FreeBSD
                 * number back, so the restart is translated like a new
                 * call. Translating the code itself leaked "error 513".
                 */
                if (state->retval == -512 /* ERESTARTSYS */ ||
                    state->retval == -513 /* ERESTARTNOINTR */ ||
                    state->retval == -514 /* ERESTARTNOHAND */) {
                    /* Restart with the FreeBSD number and the arguments
                     * the program passed (emulation may have changed them) */
                    struct user_regs_struct rr;
                    process_entry_t *pe = find_process(state->pid);
                    if (ptrace(PTRACE_GETREGS, state->pid, NULL, &rr) == 0) {
                        rr.orig_rax = state->syscall_nr;
                        if (pe) {
                            rr.rdi = pe->sc_raw_args[0];
                            rr.rsi = pe->sc_raw_args[1];
                            rr.rdx = pe->sc_raw_args[2];
                            rr.r10 = pe->sc_raw_args[3];
                            rr.r8  = pe->sc_raw_args[4];
                            rr.r9  = pe->sc_raw_args[5];
                        }
                        (void)ptrace(PTRACE_SETREGS, state->pid, NULL, &rr);
                    }
                    break;
                }
                if (state->retval == -516 /* ERESTART_RESTARTBLOCK */) {
                    /* An interrupted sleep. With no handler the kernel
                     * resumes it through Linux restart_syscall, which the
                     * next syscall entry lets through; a handler makes
                     * it EINTR (see signal_emul.c). */
                    sig_note_restart_block(state->pid);
                    break;
                }

                /* interceptor_set_return() translates the errno itself
                 * (Linux -> FreeBSD) and sets CF; translating it here too
                 * converted it twice (EAGAIN 11 -> 35 -> 11 = EDEADLK). */
                if (state->retval < 0 && state->retval > -4096) {
                    interceptor_set_return(state->pid, state->retval);
                }

                /* sigreturn/setcontext, wait4 status, and signals the
                 * syscall unblocked */
                sig_after_syscall(state->pid, state->syscall_nr, state->args);
                kq_after_syscall(state->pid, state->syscall_nr, state->args);
                msg_after_syscall(state->pid, state->syscall_nr);
                thr_after_syscall(state->pid, state->syscall_nr);
                break;
            }
            
            case EVENT_SIGNAL:
                BSD_TRACE("Signal %d received", state->signal);
                
                
                /*
                 * FreeBSD semantics: the signal module runs the
                 * program's handler (building a FreeBSD signal frame),
                 * defers it if blocked, or returns the Linux signal to
                 * inject for the default action.
                 */
                {
                    int inj = sig_on_signal(state->pid, state->signal);
                    if (inj == SIGSEGV || inj == SIGBUS || inj == SIGILL || inj == SIGFPE)
                        BSD_INFO("Fatal signal %d - process will be terminated", inj);
                    interceptor_continue_signal(state, inj);
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