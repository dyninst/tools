#pragma once

#include "InsertTimingInstr.h"

// The aggregates member contains pointers to
// per-thread array of instrumentation records
typedef struct DIOG_Aggregator {
    uint64_t index;
    DIOG_InstrRecord **aggregates;
    pthread_mutex_t mutex;
} DIOG_Aggregator;

void DIOG_initInstrRecord(DIOG_InstrRecord *record);
void DIOG_initAggregator(DIOG_Aggregator *DIOG_agg);
void DIOG_addVec(DIOG_Aggregator* DIOG_agg, DIOG_InstrRecord* thread_times);