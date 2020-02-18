#pragma once

#include <stdint.h>
#include <pthread.h>

typedef struct DIOG_InstrRecord {
    uint64_t id;
    uint64_t sync_duration;
    uint64_t call_cnt;
    uint64_t duration;
    const char *func_name;
} DIOG_InstrRecord;

typedef struct DIOG_Aggregator {
    uint64_t index;
    DIOG_InstrRecord ***aggregates;
    pthread_mutex_t mutex;
} DIOG_Aggregator;

typedef struct DIOG_StopInstra {
    int stop;
    pthread_mutex_t mutex;
} DIOG_StopInstra;