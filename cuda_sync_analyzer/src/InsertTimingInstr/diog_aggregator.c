#include "diog_aggregator.h"

void DIOG_initAggregator(DIOG_Aggregator *DIOG_agg) {
    DIOG_agg->index = 0;
    pthread_mutex_init(&(DIOG_agg->mutex), NULL);

    DIOG_agg->tids = (pid_t *) malloc(MAX_THREADS * sizeof(pid_t));

    DIOG_agg->aggregates = (DIOG_InstrRecord **) malloc(
            MAX_THREADS * sizeof(DIOG_InstrRecord *));
    DIOG_malloc_check((void *) (DIOG_agg->aggregates));
    for (int i = 0; i < MAX_THREADS; i++) {
        DIOG_agg->aggregates[i] = NULL;
    }
}

/*
 * Add pointer to a per-thread array of times to the global
 * aggregator array
 */
void DIOG_addVec(DIOG_Aggregator* DIOG_agg, DIOG_InstrRecord* thread_times) {
    pthread_mutex_lock(&(DIOG_agg->mutex));
    DIOG_agg->aggregates[DIOG_agg->index] = thread_times;
    DIOG_agg->tids[DIOG_agg->index] = gettid();
    DIOG_agg->index++;
    pthread_mutex_unlock(&(DIOG_agg->mutex));
}
