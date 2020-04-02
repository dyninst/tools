#pragma once

#include <locale.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "diog_aggregator.h"

void CPROF_print_output_csv(FILE *out, CPROF_Aggregator *CPROF_agg);
