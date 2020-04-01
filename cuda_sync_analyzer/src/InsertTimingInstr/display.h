#pragma once

#include <locale.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "diog_aggregator.h"

void DIOG_print_output_csv(FILE *out, DIOG_Aggregator *DIOG_agg);
