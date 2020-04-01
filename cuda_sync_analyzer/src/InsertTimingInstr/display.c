#include "display.h"

extern const char *__progname;

void DIOG_print_output_csv(FILE *out, DIOG_Aggregator *DIOG_agg) {

    fprintf(out, "pid=%d,executable=%s,", getpid(), __progname);

    char *hostname = (char *) malloc(sizeof(char)*100);
    if (gethostname(hostname, 100) != -1) {
        fprintf(out, "hostname=%s,", hostname);
    }
    time_t curr_time;
    if ((curr_time = time(NULL)) != -1) {
        fprintf(out, "time=%s", ctime(&curr_time));
    }

    fprintf(out, "\n%% CUDA API,TOTAL TIME (ns),SYNC TIME (ns),CALL COUNT");

    for (int i = 0; i < MAX_THREADS; i++) {
        if (DIOG_agg->aggregates[i] == NULL) break;
        fprintf(out, "\ntid=%d\n", DIOG_agg->tids[i]);

        for (int j = 0; j < MAX_PUBLIC_FUNCS; j++) {
            if (DIOG_agg->aggregates[i][j].id == 0) continue;
            fprintf(out, "%s,%lu,%lu,%lu\n",
                DIOG_agg->aggregates[i][j].func_name,
                DIOG_agg->aggregates[i][j].duration,
                DIOG_agg->aggregates[i][j].sync_duration,
                DIOG_agg->aggregates[i][j].call_cnt);
        }
    }
}
