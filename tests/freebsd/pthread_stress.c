/*
 * Run inside a FreeBSD container under bsdulator:
 *   cc -O1 -pthread -o pthread_stress pthread_stress.c && ./pthread_stress
 * Prints ALL PASSED when the thread emulation (thr_new, _umtx_op) works.
 */
/* pthread stress test for bsdulator: run inside a FreeBSD jail */
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NT 8
#define ITERS 20000

static int fails;
#define CHECK(c, m) do { if (c) printf("  ok   %s\n", m); else { printf("  FAIL %s\n", m); fails++; } } while (0)

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long counter;
static void *inc(void *a) {
    (void)a;
    for (int i = 0; i < ITERS; i++) {
        pthread_mutex_lock(&mu);
        counter++;
        pthread_mutex_unlock(&mu);
    }
    return (void *)7;
}

static pthread_mutex_t cmu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int turn, rounds_done;
#define ROUNDS 2000
static void *pingpong(void *a) {
    int me = (int)(long)a;
    for (int i = 0; i < ROUNDS; i++) {
        pthread_mutex_lock(&cmu);
        while (turn != me) pthread_cond_wait(&cv, &cmu);
        turn = 1 - me;
        rounds_done++;
        pthread_cond_broadcast(&cv);
        pthread_mutex_unlock(&cmu);
    }
    return NULL;
}

static pthread_rwlock_t rw = PTHREAD_RWLOCK_INITIALIZER;
static long shared_a, shared_b, rw_bad;
static void *rw_writer(void *a) {
    (void)a;
    for (int i = 0; i < 5000; i++) {
        pthread_rwlock_wrlock(&rw);
        shared_a++;
        shared_b++;
        pthread_rwlock_unlock(&rw);
    }
    return NULL;
}
static void *rw_reader(void *a) {
    (void)a;
    for (int i = 0; i < 5000; i++) {
        pthread_rwlock_rdlock(&rw);
        if (shared_a != shared_b) __atomic_add_fetch(&rw_bad, 1, __ATOMIC_RELAXED);
        pthread_rwlock_unlock(&rw);
    }
    return NULL;
}

static sem_t sem_items;
static long produced, consumed;
static void *producer(void *a) {
    (void)a;
    for (int i = 0; i < 3000; i++) { __atomic_add_fetch(&produced, 1, __ATOMIC_RELAXED); sem_post(&sem_items); }
    return NULL;
}
static void *consumer(void *a) {
    (void)a;
    for (int i = 0; i < 3000; i++) { sem_wait(&sem_items); __atomic_add_fetch(&consumed, 1, __ATOMIC_RELAXED); }
    return NULL;
}

static __thread int tls_val;
static void *tls_fn(void *a) {
    tls_val = (int)(long)a;
    usleep(1000);
    return (void *)(long)(tls_val == (int)(long)a);
}

static pthread_once_t once = PTHREAD_ONCE_INIT;
static int once_count;
static void once_init(void) { once_count++; }
static void *once_fn(void *a) { (void)a; pthread_once(&once, once_init); return NULL; }

static pthread_barrier_t bar;
static int before, after_bad;
static void *bar_fn(void *a) {
    (void)a;
    __atomic_add_fetch(&before, 1, __ATOMIC_SEQ_CST);
    pthread_barrier_wait(&bar);
    if (__atomic_load_n(&before, __ATOMIC_SEQ_CST) != NT) __atomic_add_fetch(&after_bad, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static volatile sig_atomic_t got_usr1;
static void on_usr1(int s) { (void)s; got_usr1 = 1; }
static void *sig_target(void *a) {
    (void)a;
    for (int i = 0; i < 200 && !got_usr1; i++) usleep(5000);
    return NULL;
}

int main(void) {
    pthread_t t[NT];
    void *rv;
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("mutex (%d threads x %d)\n", NT, ITERS);
    for (int i = 0; i < NT; i++) pthread_create(&t[i], NULL, inc, NULL);
    int joined = 0;
    for (int i = 0; i < NT; i++) { pthread_join(t[i], &rv); joined += rv == (void *)7; }
    CHECK(counter == (long)NT * ITERS, "contended mutex counter exact");
    CHECK(joined == NT, "join returns thread results");

    printf("condvar ping-pong\n");
    pthread_create(&t[0], NULL, pingpong, (void *)0L);
    pthread_create(&t[1], NULL, pingpong, (void *)1L);
    pthread_join(t[0], NULL);
    pthread_join(t[1], NULL);
    CHECK(rounds_done == 2 * ROUNDS, "condvar handoffs complete");

    printf("rwlock\n");
    for (int i = 0; i < 2; i++) pthread_create(&t[i], NULL, rw_writer, NULL);
    for (int i = 2; i < 6; i++) pthread_create(&t[i], NULL, rw_reader, NULL);
    for (int i = 0; i < 6; i++) pthread_join(t[i], NULL);
    CHECK(shared_a == 10000 && shared_b == 10000 && rw_bad == 0, "rwlock exclusion");

    printf("semaphore\n");
    sem_init(&sem_items, 0, 0);
    pthread_create(&t[0], NULL, consumer, NULL);
    pthread_create(&t[1], NULL, consumer, NULL);
    pthread_create(&t[2], NULL, producer, NULL);
    pthread_create(&t[3], NULL, producer, NULL);
    for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);
    CHECK(produced == 6000 && consumed == 6000, "semaphore producer/consumer");

    printf("tls, once, barrier\n");
    int tls_ok = 0;
    for (int i = 0; i < NT; i++) pthread_create(&t[i], NULL, tls_fn, (void *)(long)(i + 1));
    for (int i = 0; i < NT; i++) { pthread_join(t[i], &rv); tls_ok += (long)rv; }
    CHECK(tls_ok == NT, "thread-local storage per thread");
    for (int i = 0; i < NT; i++) pthread_create(&t[i], NULL, once_fn, NULL);
    for (int i = 0; i < NT; i++) pthread_join(t[i], NULL);
    CHECK(once_count == 1, "pthread_once runs once");
    pthread_barrier_init(&bar, NULL, NT);
    for (int i = 0; i < NT; i++) pthread_create(&t[i], NULL, bar_fn, NULL);
    for (int i = 0; i < NT; i++) pthread_join(t[i], NULL);
    CHECK(after_bad == 0, "barrier releases all together");

    printf("signals\n");
    signal(SIGUSR1, on_usr1);
    pthread_create(&t[0], NULL, sig_target, NULL);
    pthread_kill(t[0], SIGUSR1);
    pthread_join(t[0], NULL);
    CHECK(got_usr1 == 1, "pthread_kill runs the handler");

    printf("many threads\n");
    pthread_t many[64];
    counter = 0;
    for (int i = 0; i < 64; i++) pthread_create(&many[i], NULL, inc, NULL);
    for (int i = 0; i < 64; i++) pthread_join(many[i], NULL);
    CHECK(counter == 64L * ITERS, "64 threads, counter exact");

    printf(fails ? "%d FAILED\n" : "ALL PASSED\n", fails);
    return fails ? 1 : 0;
}
