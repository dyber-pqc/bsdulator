/*
 * BSDulator - Syscall Translation
 * Maps FreeBSD syscall numbers to Linux equivalents
 */

#ifndef BSDULATOR_SYSCALL_H
#define BSDULATOR_SYSCALL_H

#include <stdint.h>
#include <sys/types.h>

/* Syscall translation result */
typedef enum {
    SYSCALL_TRANSLATED,      /* Direct translation available */
    SYSCALL_EMULATED,        /* Requires emulation logic */
    SYSCALL_UNSUPPORTED,     /* No translation possible */
    SYSCALL_PASSTHROUGH,     /* Same on both systems */
    SYSCALL_SKIP             /* Skip this syscall entirely */
} syscall_result_t;

/* Syscall handler function type */
typedef long (*syscall_handler_t)(pid_t pid, uint64_t args[6]);

/* Syscall mapping entry */
typedef struct {
    int freebsd_nr;          /* FreeBSD syscall number */
    int linux_nr;            /* Linux syscall number (-1 if none) */
    const char *name;        /* Syscall name */
    syscall_result_t type;   /* Translation type */
    syscall_handler_t handler; /* Handler for emulated syscalls */
    int needs_arg_xlat;      /* Needs argument translation? */
    int needs_ret_xlat;      /* Needs return value translation? */
} syscall_entry_t;

/* FreeBSD syscall numbers (from sys/syscall.h) */
#define FBSD_SYS_syscall        0
#define FBSD_SYS_exit           1
#define FBSD_SYS_fork           2
#define FBSD_SYS_read           3
#define FBSD_SYS_write          4
#define FBSD_SYS_open           5
#define FBSD_SYS_close          6
#define FBSD_SYS_wait4          7
#define FBSD_SYS_link           9
#define FBSD_SYS_unlink         10
#define FBSD_SYS_chdir          12
#define FBSD_SYS_fchdir         13
#define FBSD_SYS_chmod          15
#define FBSD_SYS_chown          16
#define FBSD_SYS_break          17
#define FBSD_SYS_getpid         20
#define FBSD_SYS_mount          21
#define FBSD_SYS_unmount        22
#define FBSD_SYS_setuid         23
#define FBSD_SYS_getuid         24
#define FBSD_SYS_geteuid        25
#define FBSD_SYS_ptrace         26
#define FBSD_SYS_recvmsg        27
#define FBSD_SYS_sendmsg        28
#define FBSD_SYS_recvfrom       29
#define FBSD_SYS_accept         30
#define FBSD_SYS_getpeername    31
#define FBSD_SYS_getsockname    32
#define FBSD_SYS_access         33
#define FBSD_SYS_chflags        34
#define FBSD_SYS_fchflags       35
#define FBSD_SYS_sync           36
#define FBSD_SYS_kill           37
#define FBSD_SYS_getppid        39
#define FBSD_SYS_dup            41
#define FBSD_SYS_getegid        43
#define FBSD_SYS_profil         44
#define FBSD_SYS_ktrace         45
#define FBSD_SYS_getgid         47
#define FBSD_SYS_getlogin       49
#define FBSD_SYS_setlogin       50
#define FBSD_SYS_acct           51
#define FBSD_SYS_sigaltstack    53
#define FBSD_SYS_ioctl          54
#define FBSD_SYS_reboot         55
#define FBSD_SYS_revoke         56
#define FBSD_SYS_symlink        57
#define FBSD_SYS_readlink       58
#define FBSD_SYS_execve         59
#define FBSD_SYS_umask          60
#define FBSD_SYS_chroot         61
#define FBSD_SYS_msync          65
#define FBSD_SYS_vfork          66
#define FBSD_SYS_munmap         73
#define FBSD_SYS_mprotect       74
#define FBSD_SYS_madvise        75
#define FBSD_SYS_mincore        78
#define FBSD_SYS_getgroups      79
#define FBSD_SYS_setgroups      80
#define FBSD_SYS_getpgrp        81
#define FBSD_SYS_setpgid        82
#define FBSD_SYS_setitimer      83
#define FBSD_SYS_swapon         85
#define FBSD_SYS_getitimer      86
#define FBSD_SYS_getdtablesize  89
#define FBSD_SYS_dup2           90
#define FBSD_SYS_fcntl          92
#define FBSD_SYS_select         93
#define FBSD_SYS_fsync          95
#define FBSD_SYS_setpriority    96
#define FBSD_SYS_socket         97
#define FBSD_SYS_connect        98
#define FBSD_SYS_getpriority    100
#define FBSD_SYS_bind           104
#define FBSD_SYS_setsockopt     105
#define FBSD_SYS_listen         106
#define FBSD_SYS_gettimeofday   116
#define FBSD_SYS_getrusage      117
#define FBSD_SYS_getsockopt     118
#define FBSD_SYS_readv          120
#define FBSD_SYS_writev         121
#define FBSD_SYS_settimeofday   122
#define FBSD_SYS_fchown         123
#define FBSD_SYS_fchmod         124
#define FBSD_SYS_setreuid       126
#define FBSD_SYS_setregid       127
#define FBSD_SYS_rename         128
#define FBSD_SYS_flock          131
#define FBSD_SYS_mkfifo         132
#define FBSD_SYS_sendto         133
#define FBSD_SYS_shutdown       134
#define FBSD_SYS_socketpair     135
#define FBSD_SYS_mkdir          136
#define FBSD_SYS_rmdir          137
#define FBSD_SYS_utimes         138
#define FBSD_SYS_adjtime        140
#define FBSD_SYS_setsid         147
#define FBSD_SYS_quotactl       148
#define FBSD_SYS_nlm_syscall    154
#define FBSD_SYS_nfssvc         155
#define FBSD_SYS_lgetfh         160
#define FBSD_SYS_getfh          161
#define FBSD_SYS_sysarch        165
#define FBSD_SYS_rtprio         166
#define FBSD_SYS_semsys         169
#define FBSD_SYS_msgsys         170
#define FBSD_SYS_shmsys         171
#define FBSD_SYS_setfib         175
#define FBSD_SYS_ntp_adjtime    176
#define FBSD_SYS_setgid         181
#define FBSD_SYS_setegid        182
#define FBSD_SYS_seteuid        183
#define FBSD_SYS_pathconf       191
#define FBSD_SYS_fpathconf      192
#define FBSD_SYS_getrlimit      194
#define FBSD_SYS_setrlimit      195
#define FBSD_SYS___sysctl       202
#define FBSD_SYS_mlock          203
#define FBSD_SYS_munlock        204
#define FBSD_SYS_undelete       205
#define FBSD_SYS_futimes        206
#define FBSD_SYS_getpgid        207
#define FBSD_SYS_poll           209
#define FBSD_SYS_semget         221
#define FBSD_SYS_semop          222
#define FBSD_SYS_msgget         225
#define FBSD_SYS_msgsnd         226
#define FBSD_SYS_msgrcv         227
#define FBSD_SYS_shmat          228
#define FBSD_SYS_shmdt          230
#define FBSD_SYS_shmget         231
#define FBSD_SYS_clock_gettime  232
#define FBSD_SYS_clock_settime  233
#define FBSD_SYS_clock_getres   234
#define FBSD_SYS_ktimer_create  235
#define FBSD_SYS_ktimer_delete  236
#define FBSD_SYS_ktimer_settime 237
#define FBSD_SYS_ktimer_gettime 238
#define FBSD_SYS_ktimer_getoverrun 239
#define FBSD_SYS_nanosleep      240
#define FBSD_SYS_clock_nanosleep 244
#define FBSD_SYS_ntp_gettime    248
#define FBSD_SYS_minherit       250
#define FBSD_SYS_rfork          251
#define FBSD_SYS_issetugid      253
#define FBSD_SYS_lchown         254
#define FBSD_SYS_aio_read       255
#define FBSD_SYS_aio_write      256
#define FBSD_SYS_lio_listio     257
#define FBSD_SYS_lchmod         274
#define FBSD_SYS_lutimes        276
#define FBSD_SYS_preadv         289
#define FBSD_SYS_pwritev        290
#define FBSD_SYS_fhopen         298
#define FBSD_SYS_modnext        300
#define FBSD_SYS_modstat        301
#define FBSD_SYS_modfnext       302
#define FBSD_SYS_modfind        303
#define FBSD_SYS_kldload        304
#define FBSD_SYS_kldunload      305
#define FBSD_SYS_kldfind        306
#define FBSD_SYS_kldnext        307
#define FBSD_SYS_kldstat        308
#define FBSD_SYS_kldfirstmod    309
#define FBSD_SYS_getsid         310
#define FBSD_SYS_setresuid      311
#define FBSD_SYS_setresgid      312
#define FBSD_SYS_aio_return     314
#define FBSD_SYS_aio_suspend    315
#define FBSD_SYS_aio_cancel     316
#define FBSD_SYS_aio_error      317
#define FBSD_SYS_yield          321
#define FBSD_SYS_mlockall       324
#define FBSD_SYS_munlockall     325
#define FBSD_SYS___getcwd       326
#define FBSD_SYS_sched_setparam 327
#define FBSD_SYS_sched_getparam 328
#define FBSD_SYS_sched_setscheduler 329
#define FBSD_SYS_sched_getscheduler 330
#define FBSD_SYS_sched_yield    331
#define FBSD_SYS_sched_get_priority_max 332
#define FBSD_SYS_sched_get_priority_min 333
#define FBSD_SYS_sched_rr_get_interval 334
#define FBSD_SYS_utrace         335
#define FBSD_SYS_kldsym         337
#define FBSD_SYS_jail           338
#define FBSD_SYS_nnpfs_syscall  339
#define FBSD_SYS_sigprocmask    340
#define FBSD_SYS_sigsuspend     341
#define FBSD_SYS_sigpending     343
#define FBSD_SYS_sigtimedwait   345
#define FBSD_SYS_sigwaitinfo    346
#define FBSD_SYS___acl_get_file 347
#define FBSD_SYS___acl_set_file 348
#define FBSD_SYS___acl_get_fd   349
#define FBSD_SYS___acl_set_fd   350
#define FBSD_SYS___acl_delete_file 351
#define FBSD_SYS___acl_delete_fd 352
#define FBSD_SYS___acl_aclcheck_file 353
#define FBSD_SYS___acl_aclcheck_fd 354
#define FBSD_SYS_extattrctl     355
#define FBSD_SYS_extattr_set_file 356
#define FBSD_SYS_extattr_get_file 357
#define FBSD_SYS_extattr_delete_file 358
#define FBSD_SYS_aio_waitcomplete 359
#define FBSD_SYS_getresuid      360
#define FBSD_SYS_getresgid      361
#define FBSD_SYS_kqueue         362
#define FBSD_SYS_extattr_set_fd 371
#define FBSD_SYS_extattr_get_fd 372
#define FBSD_SYS_extattr_delete_fd 373
#define FBSD_SYS___setugid      374
#define FBSD_SYS_eaccess        376
#define FBSD_SYS_afs3_syscall   377
#define FBSD_SYS_nmount         378
#define FBSD_SYS___mac_get_proc 384
#define FBSD_SYS___mac_set_proc 385
#define FBSD_SYS___mac_get_fd   386
#define FBSD_SYS___mac_get_file 387
#define FBSD_SYS___mac_set_fd   388
#define FBSD_SYS___mac_set_file 389
#define FBSD_SYS_kenv           390
#define FBSD_SYS_lchflags       391
#define FBSD_SYS_uuidgen        392
#define FBSD_SYS_sendfile       393
#define FBSD_SYS_mac_syscall    394
#define FBSD_SYS_ksem_close     400
#define FBSD_SYS_ksem_post      401
#define FBSD_SYS_ksem_wait      402
#define FBSD_SYS_ksem_trywait   403
#define FBSD_SYS_ksem_init      404
#define FBSD_SYS_ksem_open      405
#define FBSD_SYS_ksem_unlink    406
#define FBSD_SYS_ksem_getvalue  407
#define FBSD_SYS_ksem_destroy   408
#define FBSD_SYS___mac_get_pid  409
#define FBSD_SYS___mac_get_link 410
#define FBSD_SYS___mac_set_link 411
#define FBSD_SYS_extattr_set_link 412
#define FBSD_SYS_extattr_get_link 413
#define FBSD_SYS_extattr_delete_link 414
#define FBSD_SYS___mac_execve   415
#define FBSD_SYS_sigaction      416
#define FBSD_SYS_sigreturn      417
#define FBSD_SYS_getcontext     421
#define FBSD_SYS_setcontext     422
#define FBSD_SYS_swapcontext    423
#define FBSD_SYS___acl_get_link 425
#define FBSD_SYS___acl_set_link 426
#define FBSD_SYS___acl_delete_link 427
#define FBSD_SYS___acl_aclcheck_link 428
#define FBSD_SYS_sigwait        429
#define FBSD_SYS_thr_create     430
#define FBSD_SYS_thr_exit       431
#define FBSD_SYS_thr_self       432
#define FBSD_SYS_thr_kill       433
#define FBSD_SYS_jail_attach    436
#define FBSD_SYS_extattr_list_fd 437
#define FBSD_SYS_extattr_list_file 438
#define FBSD_SYS_extattr_list_link 439
#define FBSD_SYS_ksem_timedwait 441
#define FBSD_SYS_thr_suspend    442
#define FBSD_SYS_thr_wake       443
#define FBSD_SYS_kldunloadf     444
#define FBSD_SYS_audit          445
#define FBSD_SYS_auditon        446
#define FBSD_SYS_getauid        447
#define FBSD_SYS_setauid        448
#define FBSD_SYS_getaudit       449
#define FBSD_SYS_setaudit       450
#define FBSD_SYS_getaudit_addr  451
#define FBSD_SYS_setaudit_addr  452
#define FBSD_SYS_auditctl       453
#define FBSD_SYS__umtx_op       454
#define FBSD_SYS_thr_new        455
#define FBSD_SYS_sigqueue       456
#define FBSD_SYS_kmq_open       457
#define FBSD_SYS_kmq_setattr    458
#define FBSD_SYS_kmq_timedreceive 459
#define FBSD_SYS_kmq_timedsend  460
#define FBSD_SYS_kmq_notify     461
#define FBSD_SYS_kmq_unlink     462
#define FBSD_SYS_abort2         463
#define FBSD_SYS_thr_set_name   464
#define FBSD_SYS_aio_fsync      465
#define FBSD_SYS_rtprio_thread  466
#define FBSD_SYS_sctp_peeloff   471
#define FBSD_SYS_sctp_generic_sendmsg 472
#define FBSD_SYS_sctp_generic_sendmsg_iov 473
#define FBSD_SYS_sctp_generic_recvmsg 474
#define FBSD_SYS_pread          475
#define FBSD_SYS_pwrite         476
#define FBSD_SYS_mmap           477
#define FBSD_SYS_lseek          478
#define FBSD_SYS_truncate       479
#define FBSD_SYS_ftruncate      480
#define FBSD_SYS_thr_kill2      481
#define FBSD_SYS_shm_unlink     483
#define FBSD_SYS_cpuset         484
#define FBSD_SYS_cpuset_setid   485
#define FBSD_SYS_cpuset_getid   486
#define FBSD_SYS_cpuset_getaffinity 487
#define FBSD_SYS_cpuset_setaffinity 488
#define FBSD_SYS_faccessat      489
#define FBSD_SYS_fchmodat       490
#define FBSD_SYS_fchownat       491
#define FBSD_SYS_fexecve        492
#define FBSD_SYS_futimesat      494
#define FBSD_SYS_linkat         495
#define FBSD_SYS_mkdirat        496
#define FBSD_SYS_mkfifoat       497
#define FBSD_SYS_openat         499
#define FBSD_SYS_readlinkat     500
#define FBSD_SYS_renameat       501
#define FBSD_SYS_symlinkat      502
#define FBSD_SYS_unlinkat       503
#define FBSD_SYS_posix_openpt   504
#define FBSD_SYS_jail_get       506
#define FBSD_SYS_jail_set       507
#define FBSD_SYS_jail_remove    508
#define FBSD_SYS___semctl       510
#define FBSD_SYS_msgctl         511
#define FBSD_SYS_shmctl         512
#define FBSD_SYS_lpathconf      513
#define FBSD_SYS___cap_rights_get 515
#define FBSD_SYS_cap_enter      516
#define FBSD_SYS_cap_getmode    517
#define FBSD_SYS_pdfork         518
#define FBSD_SYS_pdkill         519
#define FBSD_SYS_pdgetpid       520
#define FBSD_SYS_pselect        522
#define FBSD_SYS_getloginclass  523
#define FBSD_SYS_setloginclass  524
#define FBSD_SYS_rctl_get_racct 525
#define FBSD_SYS_rctl_get_rules 526
#define FBSD_SYS_rctl_get_limits 527
#define FBSD_SYS_rctl_add_rule  528
#define FBSD_SYS_rctl_remove_rule 529
#define FBSD_SYS_posix_fallocate 530
#define FBSD_SYS_posix_fadvise  531
#define FBSD_SYS_wait6          532
#define FBSD_SYS_cap_rights_limit 533
#define FBSD_SYS_cap_ioctls_limit 534
#define FBSD_SYS_cap_ioctls_get 535
#define FBSD_SYS_cap_fcntls_limit 536
#define FBSD_SYS_cap_fcntls_get 537
#define FBSD_SYS_bindat         538
#define FBSD_SYS_connectat      539
#define FBSD_SYS_chflagsat      540
#define FBSD_SYS_accept4        541
#define FBSD_SYS_pipe2          542
#define FBSD_SYS_aio_mlock      543
#define FBSD_SYS_procctl        544
#define FBSD_SYS_ppoll          545
#define FBSD_SYS_futimens       546
#define FBSD_SYS_utimensat      547
#define FBSD_SYS_fdatasync      550
#define FBSD_SYS_fstat          551
#define FBSD_SYS_fstatat        552
#define FBSD_SYS_fhstat         553
#define FBSD_SYS_getdirentries  554
#define FBSD_SYS_statfs         555
#define FBSD_SYS_fstatfs        556
#define FBSD_SYS_getfsstat      557
#define FBSD_SYS_fhstatfs       558
#define FBSD_SYS_mknodat        559
#define FBSD_SYS_kevent         560
#define FBSD_SYS_cpuset_getdomain 561
#define FBSD_SYS_cpuset_setdomain 562
#define FBSD_SYS_getrandom      563
#define FBSD_SYS_getfhat        564
#define FBSD_SYS_fhlink         565
#define FBSD_SYS_fhlinkat       566
#define FBSD_SYS_fhreadlink     567
#define FBSD_SYS_funlinkat      568
#define FBSD_SYS_copy_file_range 569
#define FBSD_SYS___sysctlbyname 570
#define FBSD_SYS_shm_open2      571
#define FBSD_SYS_shm_rename     572
#define FBSD_SYS_sigfastblock   573
#define FBSD_SYS___realpathat   574
#define FBSD_SYS_close_range    575
#define FBSD_SYS_rpctls_syscall 576
#define FBSD_SYS___specialfd    577
#define FBSD_SYS_aio_writev     578
#define FBSD_SYS_aio_readv      579
#define FBSD_SYS_fspacectl      580
#define FBSD_SYS_sched_getcpu   581
#define FBSD_SYS_swapoff        582
#define FBSD_SYS_kqueuex        583
#define FBSD_SYS_membarrier     584
#define FBSD_SYS_timerfd_create 585
#define FBSD_SYS_timerfd_gettime 586
#define FBSD_SYS_timerfd_settime 587
#define FBSD_SYS_kcmp           588

/* Initialize syscall tables */
int syscall_init(void);

/* Translate FreeBSD syscall to Linux */
syscall_result_t syscall_translate(int freebsd_nr, int *linux_nr);

/* Get syscall entry by FreeBSD number */
const syscall_entry_t *syscall_get_entry(int freebsd_nr);

/* Execute translated/emulated syscall */
long syscall_execute(pid_t pid, int freebsd_nr, uint64_t args[6]);

/* Get syscall name for debugging */
const char *syscall_name(int freebsd_nr);

/* Argument translation for specific syscalls */
int syscall_translate_args(int freebsd_nr, uint64_t *args);

/* Return value translation */
long syscall_translate_return(int freebsd_nr, long retval);

#endif /* BSDULATOR_SYSCALL_H */
