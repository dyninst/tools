#pragma once

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// See man 2 gettid
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)


typedef struct DIOG_InstrRecord {
    uint64_t id;
    uint64_t sync_duration;
    uint64_t call_cnt;
    uint64_t duration;
    const char *func_name;
} DIOG_InstrRecord;

// per-thread struct which maintains buffer of records to be returned to the
// user via callback
typedef struct DIOG_Buffer {
    uint64_t index;
    uint64_t size;
    DIOG_InstrRecord *records;
} DIOG_Buffer;

// The aggregates member contains pointers to
// per-thread array of instrumentation records
typedef struct DIOG_Aggregator {
    uint64_t index;
    DIOG_InstrRecord **aggregates;
    pthread_mutex_t mutex;
} DIOG_Aggregator;

// This struct is used to indicate when the instrumentation needs to stop once
// the threads are destroyed and not instrument function like cuModuleUnload, etc.
typedef struct DIOG_StopInstra {
    int stop;
    pthread_mutex_t mutex;
} DIOG_StopInstra;