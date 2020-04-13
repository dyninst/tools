#pragma once

#include "InsertTimingInstr.h"

extern int CPROF_op_to_file;
extern char CPROF_op_filename[MAX_FILENAME_SZ];

// per-thread struct which maintains buffer of records to be returned to the
// user via callback
typedef struct CPROF_Buffer {
    uint64_t index;
    uint64_t size;
    CPROF_InstrRecord *records;
} CPROF_Buffer;

extern __thread CPROF_Buffer *CPROF_buffer;
extern __thread void (*callback_func)(CPROF_Buffer *);

void CPROF_reg_callback(void (*callback)(CPROF_Buffer *), int buffer_size, int to_file,
        char *output_file);

void CPROF_callback(CPROF_Buffer * buf);