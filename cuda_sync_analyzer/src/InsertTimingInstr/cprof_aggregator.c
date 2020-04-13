#include "cprof_aggregator.h"

void CPROF_initAggregator(CPROF_Aggregator *CPROF_agg) {
    CPROF_agg->index = 0;
    pthread_mutex_init(&(CPROF_agg->mutex), NULL);

    CPROF_agg->tids = (pid_t *) malloc(MAX_THREADS * sizeof(pid_t));

    CPROF_agg->aggregates = (CPROF_InstrRecord **) malloc(
            MAX_THREADS * sizeof(CPROF_InstrRecord *));
    CPROF_malloc_check((void *) (CPROF_agg->aggregates));
    for (int i = 0; i < MAX_THREADS; i++) {
        CPROF_agg->aggregates[i] = NULL;
    }
}

/*
 * Add pointer to a per-thread array of times to the global
 * aggregator array
 */
void CPROF_addVec(CPROF_Aggregator* CPROF_agg, CPROF_InstrRecord* thread_times) {
    pthread_mutex_lock(&(CPROF_agg->mutex));
    CPROF_agg->aggregates[CPROF_agg->index] = thread_times;
    CPROF_agg->tids[CPROF_agg->index] = gettid();
    CPROF_agg->index++;
    pthread_mutex_unlock(&(CPROF_agg->mutex));
}
