#pragma once

#include "InsertTimingInstr.h"

extern int DIOG_op_to_file;
extern char DIOG_op_filename[MAX_FILENAME_SZ];

// per-thread struct which maintains buffer of records to be returned to the
// user via callback
typedef struct DIOG_Buffer {
    uint64_t index;
    uint64_t size;
    DIOG_InstrRecord *records;
} DIOG_Buffer;

extern __thread DIOG_Buffer *DIOG_buffer;
extern __thread void (*callback_func)(DIOG_Buffer *);

void DIOG_reg_callback(void (*callback)(DIOG_Buffer *), int buffer_size, int to_file,
        char *output_file);

void DIOG_callback(DIOG_Buffer * buf);