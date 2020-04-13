#pragma once

#include "InsertTimingInstr.h"

// The aggregates member contains pointers to
// per-thread array of instrumentation records
typedef struct CPROF_Aggregator {
    uint64_t index;
    CPROF_InstrRecord **aggregates;
    pid_t *tids;
    pthread_mutex_t mutex;
} CPROF_Aggregator;

void CPROF_initAggregator(CPROF_Aggregator *CPROF_agg);
void CPROF_addVec(CPROF_Aggregator* CPROF_agg, CPROF_InstrRecord* thread_times);
