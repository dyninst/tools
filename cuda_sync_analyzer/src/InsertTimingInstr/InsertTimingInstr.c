#include "InsertTimingInstr.h"

int DIOG_op_to_file = 0;
char *DIOG_op_filename = NULL;
DIOG_Aggregator *DIOG_agg = NULL;
DIOG_StopInstra *DIOG_stop_instra = NULL;

// TODO: how to get size -
// 1. pass it as argument to entry instrumentation
// 2. insert it in libcuda and fetch it here
// 3. use constant value
__thread DIOG_InstrRecord **exec_times = NULL;

// Maintain a per-thread buffer of records for individual calls
// to be returned to callback function when filled
__thread DIOG_Buffer *DIOG_buffer = NULL;

// Maintain count of unresolved API entries
__thread uint64_t stack_cnt = 0;
__thread uint64_t sync_total = 0;
__thread struct timespec api_entry, api_exit, sync_entry, sync_exit;


void DIOG_initInstrRecord(DIOG_InstrRecord *record) {
    record->id = 0;
    record->sync_duration = 0;
    record->call_cnt = 0;
    record->duration = 0;
}

void DIOG_initAggregator(DIOG_Aggregator *DIOG_agg) {
    DIOG_agg->index = 0;
    DIOG_agg->aggregates = NULL;
    pthread_mutex_init(&(DIOG_agg->mutex), NULL);
}

void DIOG_addVec(DIOG_Aggregator* DIOG_agg, DIOG_InstrRecord** thread_times) {
    pthread_mutex_lock(&(DIOG_agg->mutex));
    DIOG_agg->aggregates[DIOG_agg->index] = thread_times;
    DIOG_agg->index++;
    pthread_mutex_unlock(&(DIOG_agg->mutex));
}

void DIOG_signalStop(DIOG_StopInstra* DIOG_stop_instra) {
    pthread_mutex_lock(&(DIOG_stop_instra->mutex));
    DIOG_stop_instra->stop = 1;
    pthread_mutex_unlock(&(DIOG_stop_instra->mutex));
}

void DIOG_malloc_check(void *p) {
    if (!p) {
        fprintf(stderr, "Error on malloc!\n");
        exit(1);
    }
}

void DIOG_regCallback(void (*callback)(void), int buffer_size, int to_file,
        const char *output_file) {
    if (to_file) {
        DIOG_op_to_file = 1;
    }
    if (to_file && output_file) {
        DIOG_op_filename = output_file;
    }
    if (buffer_size <= 0)
        fprintf(stderr, "Invalid per-thread buffer size\n");

    if (!DIOG_buffer && buffer_size > 0) {
        DIOG_buffer = (DIOG_Buffer *) malloc(sizeof(DIOG_Buffer));
        if (!DIOG_buffer) {
            fprintf(stderr, "Error malloc-ing per-thread buffer\n");
            return;
        }
        DIOG_buffer->records = (DIOG_InstrRecord *) malloc(sizeof(DIOG_InstrRecord) * buffer_size);
        DIOG_malloc_check((void *) (DIOG_buffer->records));
        DIOG_buffer->index = 0;
        DIOG_buffer->size = buffer_size;
    }
}

void DIOG_examineEnvVars() {
    // Check if the env variable DIOG_TO_FILE is set to 1
    // If set, override default value for DIOG_op_to_file to 1
    // and enable output of results to file
    const char *env_op_to_file = getenv("DIOG_TO_FILE");
    if (env_op_to_file) {
        if (strtol(env_op_to_file, NULL, 10) == 1) {
            DIOG_op_to_file = 1;
        }
    }

    const char *env_filename = getenv("DIOG_FILENAME");
    if (env_filename) {
        DIOG_op_filename = env_filename;
    }
    else {
        DIOG_op_filename = "DIOG_trace_<pid>.txt";
    }
}

/**
 * Post-execution actions
 */
void DIOG_SAVE_INFO() {

    // This is set to avoid instrumenting cuModuleUnload, etc.,
    // which are called after thread is destroyed
    DIOG_signalStop(DIOG_stop_instra);

    FILE *outfile = fopen("Results.txt", "w");
    if (outfile == NULL)
        fprintf(stderr, "Error creating/opening results file!\n");

    fprintf(outfile, "PID: %d\t\tExecutable Name:\n", getpid());

    for (int i = 0; i < 1000; i++) {
        if (DIOG_agg->aggregates[i] == NULL) break;
        fprintf(outfile, "\n\nTID: %ld\n", gettid());
        for (int j = 0; j < 1000; j++) {
            if (DIOG_agg->aggregates[i][j]->id == 0) continue;
            printf("    DIOG_agg[%d][%d]\n", i, j);
            fprintf(outfile, "%s %lu %lu %lu\n",
                DIOG_agg->aggregates[i][j]->func_name,     DIOG_agg->aggregates[i][j]->duration,
                DIOG_agg->aggregates[i][j]->sync_duration, DIOG_agg->aggregates[i][j]->call_cnt);
        }
    }
    if (fclose(outfile) != 0)
        fprintf(stderr, "Error closing results file!\n");

    // TODO: free
    free(DIOG_stop_instra);
    free(DIOG_agg->aggregates);
    free(DIOG_agg);
    for (int i = 0; i < 1000; i++)
        free(exec_times[i]);
    free(exec_times);
}

/**
 * Perform initialization on the very first API entry
 * Add ptr to thread-local array (exec_times) to a global array of ptrs (aggregators)
 */
void DIOG_SignalStartInstra() {
    // std::cout << "Signal start of intrumentation" << std::endl;

    DIOG_examineEnvVars();

    if (!DIOG_stop_instra) {
        DIOG_stop_instra = (DIOG_StopInstra *) malloc(sizeof(DIOG_StopInstra));
        DIOG_malloc_check((void *) DIOG_stop_instra);
        DIOG_stop_instra->stop = 0;
        pthread_mutex_init(&(DIOG_stop_instra->mutex), NULL);
    }

    if (!DIOG_agg) {
        DIOG_agg = (DIOG_Aggregator *) malloc(sizeof(DIOG_Aggregator));
        DIOG_malloc_check((void *) DIOG_agg);

        DIOG_initAggregator(DIOG_agg);

        DIOG_agg->aggregates = (DIOG_InstrRecord ***) malloc(1000*sizeof(DIOG_InstrRecord **));
        DIOG_malloc_check((void *) (DIOG_agg->aggregates));
        for (int i = 0; i < 1000; i++) {
            DIOG_agg->aggregates[i] = NULL;
        }
    }

    if (!exec_times) {
        exec_times = (DIOG_InstrRecord **) malloc(sizeof(DIOG_InstrRecord *) * 1000);
        DIOG_malloc_check((void *) exec_times);

        for (int i = 0; i < 1000; i++) {
            exec_times[i] = (DIOG_InstrRecord *) malloc(sizeof(DIOG_InstrRecord));
            DIOG_malloc_check((void *) (exec_times[i]));

            DIOG_initInstrRecord(exec_times[i]);
        }

        DIOG_addVec(DIOG_agg, exec_times);
    }

    if (atexit(DIOG_SAVE_INFO) != 0)
        fprintf(stderr, "Failed to register atexit function\n");
}

/**
 * API entry instrumentation
 * Increments stack_cnt, denoting number of public functions in the current call stack
 */
void DIOG_API_ENTRY(uint64_t offset) {
    // std::cout << "-------Start timer" << std::endl;
    if (exec_times == NULL)
        DIOG_SignalStartInstra();

    if (DIOG_stop_instra->stop) return;
    stack_cnt++;
    if (stack_cnt > 1) return; // 

    if (clock_gettime(CLOCK_REALTIME, &api_entry) == -1) {
        fprintf(stderr, "clock_gettime failed for entry instrumentation\n");
    }
}

/**
 * API exit instrumentation
 * Store instrumentation for the API in a thread-local vector
 */
void DIOG_API_EXIT(uint64_t offset, uint64_t id, const char *name) {
    // std::cout << "id: " << id << std::endl;
    if (DIOG_stop_instra->stop) return;
    stack_cnt--;
    // stack_cnt > 0 means this API is called from within another API
    if (stack_cnt > 0) return;

    if (clock_gettime(CLOCK_REALTIME, &api_exit) == -1) {
        fprintf(stderr, "clock_gettime failed for exit instrumentation\n");
    }
    // std::cout << "-------Stopped timer for " << name << ", id: " << id << std::endl;

    uint64_t duration = (uint64_t) (api_exit.tv_nsec - api_entry.tv_nsec)
       + (uint64_t) (api_exit.tv_sec - api_entry.tv_sec) * 1000000000;
    exec_times[id]->id = id;
    exec_times[id]->duration += duration;
    exec_times[id]->sync_duration += sync_total;
    exec_times[id]->call_cnt++;
    exec_times[id]->func_name = name;

    if (DIOG_buffer) {
        uint64_t index = DIOG_buffer->index;
        if (index == DIOG_buffer->size) {
            // callback buffer
        }
        else {
            DIOG_buffer->records[index].id = id;
            DIOG_buffer->records[index].duration = duration;
            DIOG_buffer->records[index].sync_duration = sync_total;
            DIOG_buffer->records[index].call_cnt = 1;
            DIOG_buffer->records[index].func_name = name;
            DIOG_buffer->index++;
        }
    }

    sync_total = 0;
}

/**
 * Synchronization entry instrumentation
 */
void DIOG_SYNC_ENTRY(uint64_t offset) {
    if (DIOG_stop_instra->stop) return;
    // Case when synchronization function is called by a non-public function
    if (stack_cnt == 0) return;
    // std::cout << "start sync ..." << std::endl;
    if (clock_gettime(CLOCK_REALTIME, &sync_entry) == -1) {
        fprintf(stderr, "clock_gettime failed for syn entry instrumentation\n");
    }
}

/**
 * Synchronization exit instrumentation
 */
void DIOG_SYNC_EXIT(uint64_t offset) {
    if (DIOG_stop_instra->stop) return;
    // std::cout << "Stop sync timer" << std::endl;
    // Case when synchronization function is called by a non-public function
    if (stack_cnt == 0) return;
    if (clock_gettime(CLOCK_REALTIME, &sync_exit) == -1) {
        fprintf(stderr, "clock_gettime failed for syn exit instrumentation\n");
    }
    // std::cout << "stopped sync" << std::endl;

    sync_total += ((uint64_t) (sync_exit.tv_nsec - sync_entry.tv_nsec)
       + (uint64_t) (sync_exit.tv_sec - sync_entry.tv_sec) * 1000000000);
}
