#include "InsertTimingInstr.h"
#include "diog_buffer.h"
#include "diog_aggregator.h"
#include "display.h"


int CPROF_op_to_file = 0, CPROF_print_op = 0;
char CPROF_op_filename[MAX_FILENAME_SZ];
CPROF_Aggregator *CPROF_agg = NULL;
CPROF_StopInstra *CPROF_stop_instra = NULL;
pthread_mutex_t CPROF_init_globals = PTHREAD_MUTEX_INITIALIZER;

// Per-thread array to store timing info per API function
__thread CPROF_InstrRecord *exec_times = NULL;

// Maintain a per-thread buffer of records for individual calls
// to be returned to callback function when filled
__thread CPROF_Buffer *CPROF_buffer = NULL;
__thread void (*callback_func)(CPROF_Buffer *) = NULL;

// Maintain count of unresolved API entries
__thread uint64_t stack_cnt = 0;
__thread uint64_t sync_total = 0;
__thread struct timespec api_entry, api_exit, sync_entry, sync_exit;


void CPROF_initInstrRecord(CPROF_InstrRecord *record) {
    record->id = 0;
    record->sync_duration = 0;
    record->call_cnt = 0;
    record->duration = 0;
}

void CPROF_malloc_check(void *p) {
    if (!p) {
        fprintf(stderr, "[InsertTimingInstr] Error on malloc!\n");
        exit(1);
    }
}

/*
 * Called when we want to stop instrumenting further calls
 * Eg. - Functions like cuModuleUnload which are called after program exit
 */
void CPROF_signalStop(CPROF_StopInstra* CPROF_stop_instra) {
    pthread_mutex_lock(&(CPROF_stop_instra->mutex));
    CPROF_stop_instra->stop = 1;
    pthread_mutex_unlock(&(CPROF_stop_instra->mutex));
}

void CPROF_test_callback() {
    CPROF_reg_callback(CPROF_callback, 50, 1, NULL);
}

/**
 * Override the default values to store results using env variables
 * 
 * CPROF_TO_FILE - 1 => redirects all output to a file
 * CPROF_FILENAME - <filename> => optional file name
 */
void CPROF_examine_env_vars() {
    // Check if the env variable CPROF_TO_FILE is set to 1
    // If set, override default value for CPROF_op_to_file to 1
    // and enable output of results to file
    const char *env_op_to_file = getenv("CPROF_TO_FILE");
    if (env_op_to_file) {
        if (strtol(env_op_to_file, NULL, 10) == 1) {
            CPROF_op_to_file = 1;
        }
    }

    const char *env_print_op = getenv("CPROF_PRINT");
    if (env_print_op) {
        if (strtol(env_print_op, NULL, 10) == 1) {
            CPROF_print_op = 1;
        }
    }

    char *env_filename = getenv("CPROF_FILENAME");
    if (env_filename) {
        strncpy(CPROF_op_filename, env_filename, sizeof(CPROF_op_filename) / sizeof(char));
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
void CPROF_SAVE_INFO() {

    // callback with whatever entries are left in the buffer
    if (CPROF_buffer && CPROF_buffer->index > 0) {
        (*callback_func)(CPROF_buffer);
        CPROF_buffer->index = 0;
    }

    // This is set to avoid instrumenting cuModuleUnload, etc.,
    // which are called after thread is destroyed
    CPROF_signalStop(CPROF_stop_instra);

    FILE *outfile = NULL;
    if (CPROF_op_to_file) {
        // Set default filename if none specified
        if (strlen(CPROF_op_filename) == 0) {
            pid_t pid = getpid();
            char pid_str[10];
            sprintf(pid_str, "%d", pid);
            strcpy(CPROF_op_filename, "diogresults_");
            strcat(CPROF_op_filename, pid_str);
            strcat(CPROF_op_filename, ".txt");
        }
        FILE *file = fopen(CPROF_op_filename, "w");
        outfile = file;
    }
    else {
        outfile = stdout;
    }
    if (outfile == NULL)
        fprintf(stderr, "Error creating/opening results file!\n");

    if (outfile == stdout) {
        if (CPROF_print_op)
            CPROF_print_output_csv(outfile, CPROF_agg);
    } else {
        CPROF_print_output_csv(outfile, CPROF_agg);
    }

    if (outfile != stdout && fclose(outfile) != 0)
        fprintf(stderr, "Error closing results file!\n");

    // free-ing CPROF_stop_instra causes API functions run after atexit
    // for eg., cumModuleUnload to run instrumentation code, which should not happen
    // free(CPROF_stop_instra);

    if (CPROF_buffer) {
        free(CPROF_buffer->records);
        free(CPROF_buffer);
    }
    free(CPROF_agg->aggregates);
    free(CPROF_agg->tids);
    free(CPROF_agg);
    free(exec_times);
}

/**
 * Perform initialization of data structures on the very first API entry
 */
void CPROF_SignalStartInstra() {

    CPROF_examine_env_vars();

    if (!CPROF_stop_instra) {
        // Only one thread should come in and initialize these globals
        pthread_mutex_lock(&CPROF_init_globals);

        if (!CPROF_stop_instra) {
            CPROF_stop_instra = (CPROF_StopInstra *) malloc(sizeof(CPROF_StopInstra));
            CPROF_malloc_check((void *) CPROF_stop_instra);
            CPROF_stop_instra->stop = 0;
            pthread_mutex_init(&(CPROF_stop_instra->mutex), NULL);

            if (atexit(CPROF_SAVE_INFO) != 0)
                fprintf(stderr, "Failed to register atexit function\n");
        }

        if (!CPROF_agg) {
            CPROF_agg = (CPROF_Aggregator *) malloc(sizeof(CPROF_Aggregator));
            CPROF_malloc_check((void *) CPROF_agg);

            CPROF_initAggregator(CPROF_agg);
        }
        pthread_mutex_unlock(&CPROF_init_globals);
    }

    if (!exec_times) {
        exec_times = (CPROF_InstrRecord *) malloc(
                sizeof(CPROF_InstrRecord) * MAX_PUBLIC_FUNCS);
        CPROF_malloc_check((void *) exec_times);

        for (int i = 0; i < MAX_PUBLIC_FUNCS; i++) {
            CPROF_initInstrRecord(exec_times + i);
        }

        CPROF_addVec(CPROF_agg, exec_times);
    }

    // CPROF_test_callback();
}

/**
 * API entry instrumentation
 * Increments stack_cnt, denoting number of public functions in the current call stack
 */
void CPROF_API_ENTRY(uint64_t offset) {
    if (exec_times == NULL)
        CPROF_SignalStartInstra();

    if (CPROF_stop_instra->stop) return;
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
void CPROF_API_EXIT(uint64_t offset, uint64_t id, const char *name) {
    if (CPROF_stop_instra->stop) return;

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

    if (CPROF_buffer) {
        uint64_t index = CPROF_buffer->index;
        CPROF_buffer->records[index].id = id;
        CPROF_buffer->records[index].duration = duration;
        CPROF_buffer->records[index].sync_duration = sync_total;
        CPROF_buffer->records[index].call_cnt = 1;
        CPROF_buffer->records[index].func_name = name;
        CPROF_buffer->index++;

        // If buffer is full, callback with the buffer
        if (CPROF_buffer->index == CPROF_buffer->size) {
            (*callback_func)(CPROF_buffer);
            CPROF_buffer->index = 0;
        }
    }

    sync_total = 0;
}

/**
 * Synchronization entry instrumentation
 */
void CPROF_SYNC_ENTRY(uint64_t offset) {
    if (CPROF_stop_instra->stop) return;

    // Case when synchronization function is called by a non-public function
    if (stack_cnt == 0) return;

    if (clock_gettime(CLOCK_REALTIME, &sync_entry) == -1) {
        fprintf(stderr, "clock_gettime failed for syn entry instrumentation\n");
    }
}

/**
 * Synchronization exit instrumentation
 */
void CPROF_SYNC_EXIT(uint64_t offset) {
    if (CPROF_stop_instra->stop) return;

    // Case when synchronization function is called by a non-public function
    if (stack_cnt == 0) return;

    if (clock_gettime(CLOCK_REALTIME, &sync_exit) == -1) {
        fprintf(stderr, "clock_gettime failed for syn exit instrumentation\n");
    }

    sync_total += ((uint64_t) (sync_exit.tv_nsec - sync_entry.tv_nsec)
       + (uint64_t) (sync_exit.tv_sec - sync_entry.tv_sec) * SEC_TO_NS);
}
