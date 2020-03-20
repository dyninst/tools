#include "InsertTimingInstr.h"
#include "diog_buffer.h"
#include "diog_aggregator.h"
#include "display.h"


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


void DIOG_initInstrRecord(DIOG_InstrRecord *record) {
    record->id = 0;
    record->sync_duration = 0;
    record->call_cnt = 0;
    record->duration = 0;
}

void DIOG_malloc_check(void *p) {
    if (!p) {
        fprintf(stderr, "[InsertTimingInstr] Error on malloc!\n");
        exit(1);
    }
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

void DIOG_test_callback() {
    DIOG_reg_callback(DIOG_callback, 50, 1, NULL);
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

    if (outfile == stdout)
        DIOG_print_output(outfile, DIOG_agg);
    else
        DIOG_print_output_csv(outfile, DIOG_agg);

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
    free(DIOG_agg->tids);
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

    // DIOG_test_callback();
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
    if (stack_cnt > 1) return;

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
