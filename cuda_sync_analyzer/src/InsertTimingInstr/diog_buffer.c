#include "diog_buffer.h"

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

void DIOG_callback(DIOG_Buffer * buf) {
    printf("Print func names from callback results\n");
    for(int i = 0; i < buf->index; i++) {
        printf("%s\t%lu ns\n", buf->records[i].func_name, buf->records[i].duration);
    }
}