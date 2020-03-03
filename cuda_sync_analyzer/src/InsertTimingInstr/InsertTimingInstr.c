#include "InsertTimingInstr.h"


int DIOG_op_to_file = 0;
char DIOG_op_filename[MAX_FILENAME_SZ];
DIOG_Aggregator *DIOG_agg = NULL;
DIOG_StopInstra *DIOG_stop_instra = NULL;

// TODO: how to get size -
// 1. pass it as argument to entry instrumentation
// 2. insert it in libcuda and fetch it here
// 3. use constant value
__thread DIOG_InstrRecord *exec_times = NULL;

// Maintain a per-thread buffer of records for individual calls
// to be returned to callback function when filled
__thread DIOG_Buffer *DIOG_buffer = NULL;
__thread void (*callback_func)(DIOG_Buffer *) = NULL;

// Maintain count of unresolved API entries
__thread uint64_t stack_cnt = 0;
__thread uint64_t sync_total = 0;
__thread struct timespec api_entry, api_exit, sync_entry, sync_exit;

extern const char *__progname;


void DIOG_malloc_check(void *p) {
    if (!p) {
        fprintf(stderr, "[InsertTimingInstr] Error on malloc!\n");
        exit(1);
    }
}

void DIOG_initInstrRecord(DIOG_InstrRecord *record) {
    record->id = 0;
    record->sync_duration = 0;
    record->call_cnt = 0;
    record->duration = 0;
}

void DIOG_initAggregator(DIOG_Aggregator *DIOG_agg) {
    DIOG_agg->index = 0;
    pthread_mutex_init(&(DIOG_agg->mutex), NULL);

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
    DIOG_agg->index++;
    pthread_mutex_unlock(&(DIOG_agg->mutex));
}

/*
 * Called when we want to stop instrumenting further calls
 * Eg. - Functions like cuModuleUnload which are called after program exit
 */
void DIOG_signalStop(DIOG_StopInstra* DIOG_stop_instra) {
    pthread_mutex_lock(&(DIOG_stop_instra->mutex));
    DIOG_stop_instra->stop = 1;
    pthread_mutex_unlock(&(DIOG_stop_instra->mutex));
}

void DIOG_callback(DIOG_Buffer * buf) {
    printf("Print func names from callback results\n");
    for(int i = 0; i < buf->index; i++) {
        printf("%s\t%lu ns\n", buf->records[i].func_name, buf->records[i].duration);
    }
}

/**
 * Function to register callbacks
 * Will call the callback function with results of latest
 * buffer_size API times
 *
 * callback - Callback function to be executed
 * buffer_size - Size of buffer to be returned to the callback function
 * to_file - If 1, redirects all output to a file
 * output_file - If specified, stores output in a file with that name
 */
void DIOG_reg_callback(void (*callback)(DIOG_Buffer *), int buffer_size, int to_file,
        char *output_file) {

    callback_func = callback;

    if (to_file) {
        DIOG_op_to_file = 1;
    }
    if (to_file && output_file) {
        // sanitise file name
        strncpy(DIOG_op_filename, output_file, sizeof(DIOG_op_filename) / sizeof(char));
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

void DIOG_test_callback() {
    DIOG_reg_callback(DIOG_callback, 50, 1, "results.txt");
}

/**
 * Override the default values to store results using env variables
 * 
 * DIOG_TO_FILE - 1 => redirects all output to a file
 * DIOG_FILENAME - <filename> => optional file name
 */
void DIOG_examine_env_vars() {
    // Check if the env variable DIOG_TO_FILE is set to 1
    // If set, override default value for DIOG_op_to_file to 1
    // and enable output of results to file
    const char *env_op_to_file = getenv("DIOG_TO_FILE");
    if (env_op_to_file) {
        if (strtol(env_op_to_file, NULL, 10) == 1) {
            DIOG_op_to_file = 1;
        }
    }

    char *env_filename = getenv("DIOG_FILENAME");
    if (env_filename) {
        strncpy(DIOG_op_filename, env_filename, sizeof(DIOG_op_filename) / sizeof(char));
    }
}

/**
 * Post-execution actions
 *
 * Call callback function with remaining buffer entries
 * Set a flag to stop any further data collection
 * Print propperly formatted results to stdout/file as specified by user
 * Free memory for malloc-ed structures
 */
void DIOG_SAVE_INFO() {

    // callback with whatever entries are left in the buffer
    if (DIOG_buffer && DIOG_buffer->index > 0) {
        (*callback_func)(DIOG_buffer);
        DIOG_buffer->index = 0;
    }

    // This is set to avoid instrumenting cuModuleUnload, etc.,
    // which are called after thread is destroyed
    DIOG_signalStop(DIOG_stop_instra);

    FILE *outfile = NULL;
    if (DIOG_op_to_file) {
        // Set default filename if none specified
        if (strlen(DIOG_op_filename) == 0) {
            pid_t pid = getpid();
            char pid_str[10];
            sprintf(pid_str, "%d", pid);
            strcpy(DIOG_op_filename, "diogresults_");
            strcat(DIOG_op_filename, pid_str);
            strcat(DIOG_op_filename, ".txt");
        }
        FILE *file = fopen(DIOG_op_filename, "w");
        outfile = file;
    }
    else {
        outfile = stdout;
    }
    if (outfile == NULL)
        fprintf(stderr, "Error creating/opening results file!\n");

    int width1 = 30, width2 = 15;
    fprintf(outfile, "PID: %d\tEXECUTABLE: %s\t", getpid(), __progname);

    char *hostname = (char *) malloc(sizeof(char)*100);
    if (gethostname(hostname, 100) != -1) {
        fprintf(outfile, "HOSTNAME: %s\n", hostname);
    }
    time_t curr_time;
    if ((curr_time = time(NULL)) != -1) {
        fprintf(outfile, "TIME: %s\n", ctime(&curr_time));
    }

    fprintf(outfile, "\n%*s %*s %*s %*s\n", width1, "CUDA API",
        width2, "TOTAL TIME (ns)", width2, "SYNC TIME (ns)",
        width2, "CALL COUNT");
    for (int i = 0; i < MAX_THREADS; i++) {
        if (DIOG_agg->aggregates[i] == NULL) break;
        // TODO: TID below will be the same for all threads
        fprintf(outfile, "\nTHREAD ID: %ld\n", gettid());
        for (int j = 0; j < MAX_PUBLIC_FUNCS; j++) {
            if (DIOG_agg->aggregates[i][j].id == 0) continue;
            fprintf(outfile, "%*s %*lu %*lu %*lu\n",
                width1, DIOG_agg->aggregates[i][j].func_name,
                width2, DIOG_agg->aggregates[i][j].duration,
                width2, DIOG_agg->aggregates[i][j].sync_duration,
                width2, DIOG_agg->aggregates[i][j].call_cnt);
        }
    }
    if (outfile != stdout && fclose(outfile) != 0)
        fprintf(stderr, "Error closing results file!\n");

    // free-ing DIOG_stop_instra causes API functions run after atexit
    // for eg., cumModuleUnload to run instrumentation code, which should not happen
    // free(DIOG_stop_instra);

    if (DIOG_buffer) {
        free(DIOG_buffer->records);
        free(DIOG_buffer);
    }
    free(DIOG_agg->aggregates);
    free(DIOG_agg);
    free(exec_times);
}

/**
 * Perform initialization of data structures on the very first API entry
 */
void DIOG_SignalStartInstra() {
    DIOG_examine_env_vars();

    if (!DIOG_stop_instra) {
        DIOG_stop_instra = (DIOG_StopInstra *) malloc(sizeof(DIOG_StopInstra));
        DIOG_malloc_check((void *) DIOG_stop_instra);
        DIOG_stop_instra->stop = 0;
        pthread_mutex_init(&(DIOG_stop_instra->mutex), NULL);

        // TODO: register this only once
        // SignalStartInstra can be called more than once from different threads?!?
        if (atexit(DIOG_SAVE_INFO) != 0)
            fprintf(stderr, "Failed to register atexit function\n");
    }

    if (!DIOG_agg) {
        DIOG_agg = (DIOG_Aggregator *) malloc(sizeof(DIOG_Aggregator));
        DIOG_malloc_check((void *) DIOG_agg);

        DIOG_initAggregator(DIOG_agg);
    }

    if (!exec_times) {
        exec_times = (DIOG_InstrRecord *) malloc(
                sizeof(DIOG_InstrRecord) * MAX_PUBLIC_FUNCS);
        DIOG_malloc_check((void *) exec_times);

        for (int i = 0; i < MAX_PUBLIC_FUNCS; i++) {
            DIOG_initInstrRecord(exec_times + i);
        }

        DIOG_addVec(DIOG_agg, exec_times);
    }

    DIOG_test_callback();
}

/**
 * API entry instrumentation
 * Increments stack_cnt, denoting number of public functions in the current call stack
 */
void DIOG_API_ENTRY(uint64_t offset) {
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
    if (DIOG_stop_instra->stop) return;

    stack_cnt--;
    // stack_cnt > 0 means this API is called from within another API
    if (stack_cnt > 0) return;

    if (clock_gettime(CLOCK_REALTIME, &api_exit) == -1) {
        fprintf(stderr, "clock_gettime failed for exit instrumentation\n");
    }

    uint64_t duration = (uint64_t) (api_exit.tv_nsec - api_entry.tv_nsec)
       + (uint64_t) (api_exit.tv_sec - api_entry.tv_sec) * SEC_TO_NS;
    exec_times[id].id = id;
    exec_times[id].duration += duration;
    exec_times[id].sync_duration += sync_total;
    exec_times[id].call_cnt++;
    exec_times[id].func_name = name;

    if (DIOG_buffer) {
        uint64_t index = DIOG_buffer->index;
        DIOG_buffer->records[index].id = id;
        DIOG_buffer->records[index].duration = duration;
        DIOG_buffer->records[index].sync_duration = sync_total;
        DIOG_buffer->records[index].call_cnt = 1;
        DIOG_buffer->records[index].func_name = name;
        DIOG_buffer->index++;

        // If buffer is full, callback with the buffer
        if (DIOG_buffer->index == DIOG_buffer->size) {
            (*callback_func)(DIOG_buffer);
            DIOG_buffer->index = 0;
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

    if (clock_gettime(CLOCK_REALTIME, &sync_entry) == -1) {
        fprintf(stderr, "clock_gettime failed for syn entry instrumentation\n");
    }
}

/**
 * Synchronization exit instrumentation
 */
void DIOG_SYNC_EXIT(uint64_t offset) {
    if (DIOG_stop_instra->stop) return;

    // Case when synchronization function is called by a non-public function
    if (stack_cnt == 0) return;

    if (clock_gettime(CLOCK_REALTIME, &sync_exit) == -1) {
        fprintf(stderr, "clock_gettime failed for syn exit instrumentation\n");
    }

    sync_total += ((uint64_t) (sync_exit.tv_nsec - sync_entry.tv_nsec)
       + (uint64_t) (sync_exit.tv_sec - sync_entry.tv_sec) * SEC_TO_NS);
}
