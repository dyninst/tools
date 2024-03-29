#pragma once

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// See man 2 gettid
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)

#define MAX_FILENAME_SZ 256
#define MAX_THREADS 1000
#define MAX_PUBLIC_FUNCS 1000
#define SEC_TO_NS 1000000000


typedef struct CPROF_InstrRecord {
    uint64_t id;
    uint64_t sync_duration;
    uint64_t call_cnt;
    uint64_t duration;
    const char *func_name;
} CPROF_InstrRecord;

// This struct is used to indicate when the instrumentation needs to stop once
// the threads are destroyed and not instrument function like cuModuleUnload, etc.
typedef struct CPROF_StopInstra {
    int stop;
    pthread_mutex_t mutex;
} CPROF_StopInstra;

void CPROF_malloc_check(void *p);
