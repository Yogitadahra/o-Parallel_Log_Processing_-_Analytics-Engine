/*
 * ============================================================
 *  Parallel Log Processing & Analytics Engine
 *  OS Project Shivam, Yogita, Jeevan
 *  Language : C  |  Sync : pthreads + mutex + semaphore
 * ============================================================
 */

#include <stdio.h>       
#include <stdlib.h>      
#include <string.h>      
#include <pthread.h>      
#include <semaphore.h>   
#include <time.h>         


#define NUM_THREADS        4      
#define MAX_LINE_LEN       512    
#define MAX_DISK_READERS   2       
#define LOG_FILE           "sample.log"
#define REPORT_FILE        "report.txt"


#define SEV_INFO     "INFO"
#define SEV_WARNING  "WARNING"
#define SEV_ERROR    "ERROR"
#define SEV_CRITICAL "CRITICAL"


const char *PATTERNS[] = { "failed", "unauthorized", "attack", "denied", "timeout" };
#define NUM_PATTERNS 5


typedef struct {
    long info_count;
    long warning_count;
    long error_count;
    long critical_count;
    long pattern_hits[NUM_PATTERNS];   
    long total_lines;
} Stats;

Stats global_stats = {0};           

long progress_lines[NUM_THREADS];  
long total_lines_per_thread[NUM_THREADS]; 
volatile int threads_done = 0;      


pthread_mutex_t stats_mutex;        
sem_t           disk_semaphore;    

typedef struct {
    int    thread_id;
    long   start_byte;  
    long   end_byte;     
} ThreadTask;


void classify_line(const char *line, Stats *local)
{
    local->total_lines++;


    if (strstr(line, SEV_CRITICAL)){
        local->critical_count++;
    }
    else if (strstr(line, SEV_ERROR)){
        local->error_count++;
    }
    else if (strstr(line, SEV_WARNING)){ 
        local->warning_count++;
    }
    else if (strstr(line, SEV_INFO)){
        local->info_count++;
    }


    for (int i = 0; i < NUM_PATTERNS; i++) {
        if (strstr(line, PATTERNS[i]))
            local->pattern_hits[i]++;
    }
}


#define BAR_WIDTH 30   

void print_progress_bars(void)
{

    static int first_print = 1;
    if (!first_print) {
        for (int i = 0; i < NUM_THREADS; i++)
            printf("\033[A");   // move cursor up one line
    }
    first_print = 0;

    for (int i = 0; i < NUM_THREADS; i++) {
        long done  = progress_lines[i];
        long total = total_lines_per_thread[i];

    
        float pct  = (total > 0) ? (float)done / total : 0.0f;
        int   filled = (int)(pct * BAR_WIDTH);

    
        printf("Thread %d  [", i + 1);

        for (int b = 0; b < BAR_WIDTH; b++) {
            if (b < filled){      
                printf("=");  
            }
            else if (b == filled){   
                printf(">");
            }   
            else {
                printf(" ");
            }
        }

        printf("]  %3d%%  (%ld/%ld lines)\n",
               (int)(pct * 100), done, total);
    }
    fflush(stdout);   
}


void *worker(void *arg)
{
    ThreadTask *task = (ThreadTask *)arg;

    printf("[Thread %d] Starting — bytes %ld to %ld\n",
           task->thread_id, task->start_byte, task->end_byte);

    
    sem_wait(&disk_semaphore);         

  
    FILE *fp = fopen(LOG_FILE, "r");
    if (!fp) {
        fprintf(stderr, "[Thread %d] ERROR: Cannot open log file!\n", task->thread_id);
        sem_post(&disk_semaphore);
        pthread_exit(NULL);
    }
    fseek(fp, task->start_byte, SEEK_SET);


    Stats local_stats = {0};
    char  line[MAX_LINE_LEN];
    long  current_pos;


    long line_count = 0;
    while (ftell(fp) < task->end_byte && fgets(line, MAX_LINE_LEN, fp))
        line_count++;
    total_lines_per_thread[task->thread_id - 1] = line_count;

    fseek(fp, task->start_byte, SEEK_SET);

    while ((current_pos = ftell(fp)) < task->end_byte && fgets(line, MAX_LINE_LEN, fp)) {
        classify_line(line, &local_stats);

     
        progress_lines[task->thread_id - 1] = local_stats.total_lines;
    }

    fclose(fp);

    sem_post(&disk_semaphore);

    pthread_mutex_lock(&stats_mutex);

        global_stats.total_lines += local_stats.total_lines;
        global_stats.info_count += local_stats.info_count;
        global_stats.warning_count += local_stats.warning_count;
        global_stats.error_count += local_stats.error_count;
        global_stats.critical_count += local_stats.critical_count;

        for (int i = 0; i < NUM_PATTERNS; i++)
            global_stats.pattern_hits[i] += local_stats.pattern_hits[i];

    pthread_mutex_unlock(&stats_mutex);

    __sync_fetch_and_add(&threads_done, 1); 

    pthread_exit(NULL);
}


void generate_log_file(int num_lines)
{
    const char *levels[]   = { SEV_INFO, SEV_WARNING, SEV_ERROR, SEV_CRITICAL };
    const char *messages[] = {
        "User login successful",
        "Disk space running low",
        "Database connection failed",
        "Unauthorized access attempt detected",
        "Service started normally",
        "timeout reached on connection",
        "attack pattern identified in traffic",
        "File read operation completed",
        "denied request from ip 192.168.1.5",
        "Backup completed successfully"
    };

    int nl = sizeof(levels)   / sizeof(levels[0]);
    int nm = sizeof(messages) / sizeof(messages[0]);

    FILE *fp = fopen(LOG_FILE, "w");
    if (!fp) { fprintf(stderr, "Cannot create log file!\n"); exit(1); }

    for (int i = 0; i < num_lines; i++) {
        int lvl = i % nl;
        int msg = i % nm;
        fprintf(fp, "2024-01-15 %02d:%02d:%02d  %-8s  %s\n",
                (i / 3600) % 24, (i / 60) % 60, i % 60,
                levels[lvl], messages[msg]);
    }
    fclose(fp);
    printf("[Generator] Created '%s' with %d lines.\n\n", LOG_FILE, num_lines);
}



Stats sequential_process(void)
{
    Stats s = {0};
    FILE *fp = fopen(LOG_FILE, "r");
    if (!fp) { fprintf(stderr, "Cannot open log file!\n"); exit(1); }

    char line[MAX_LINE_LEN];
    while (fgets(line, MAX_LINE_LEN, fp))
        classify_line(line, &s);

    fclose(fp);
    return s;
}



void export_report(double seq_time, double par_time)
{
    FILE *fp = fopen(REPORT_FILE, "w");
    if (!fp) { fprintf(stderr, "Cannot create report!\n"); return; }

    fprintf(fp, "========================================\n");
    fprintf(fp, "   PARALLEL LOG PROCESSING — REPORT\n");
    fprintf(fp, "========================================\n\n");

    fprintf(fp, "--- Severity Breakdown ---\n");
    fprintf(fp, "  INFO     : %ld\n", global_stats.info_count);
    fprintf(fp, "  WARNING  : %ld\n", global_stats.warning_count);
    fprintf(fp, "  ERROR    : %ld\n", global_stats.error_count);
    fprintf(fp, "  CRITICAL : %ld\n", global_stats.critical_count);
    fprintf(fp, "  TOTAL    : %ld\n\n", global_stats.total_lines);

    fprintf(fp, "--- Anomaly / Pattern Hits ---\n");
    for (int i = 0; i < NUM_PATTERNS; i++)
        fprintf(fp, "  %-15s : %ld\n", PATTERNS[i], global_stats.pattern_hits[i]);

    fprintf(fp, "\n--- Speed Benchmark ---\n");
    fprintf(fp, "  Sequential time : %.4f seconds\n", seq_time);
    fprintf(fp, "  Parallel time   : %.4f seconds\n", par_time);
    fprintf(fp, "  Speedup factor  : %.2fx\n", seq_time / par_time);

    fclose(fp);
    printf("\n[Report] Saved to '%s'\n", REPORT_FILE);
}


int main(void)
{
   
    generate_log_file(100000);

    printf("[Benchmark] Running sequential processing...\n");
    clock_t seq_start = clock();
    Stats   seq_stats = sequential_process();
    clock_t seq_end   = clock();
    double  seq_time  = (double)(seq_end - seq_start) / CLOCKS_PER_SEC;
    printf("[Benchmark] Sequential done in %.4f seconds. Lines=%ld\n\n",
           seq_time, seq_stats.total_lines);

  
    pthread_mutex_init(&stats_mutex, NULL);
    sem_init(&disk_semaphore, 0, MAX_DISK_READERS);


    FILE *fp = fopen(LOG_FILE, "r");
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fclose(fp);

    long chunk_size = file_size / NUM_THREADS;

    pthread_t  threads[NUM_THREADS];
    ThreadTask tasks[NUM_THREADS];

    printf("[Main] Spawning %d threads (file size = %ld bytes, chunk = %ld bytes)\n",
           NUM_THREADS, file_size, chunk_size);

    clock_t par_start = clock();

    for (int i = 0; i < NUM_THREADS; i++) {
        tasks[i].thread_id  = i + 1;
        tasks[i].start_byte = i * chunk_size;
        tasks[i].end_byte   = (i == NUM_THREADS - 1) ? file_size : (i + 1) * chunk_size;
        pthread_create(&threads[i], NULL, worker, &tasks[i]);
    }


    printf("\n");  
    while (threads_done < NUM_THREADS) {
        print_progress_bars();
       
        struct timespec ts = {0, 100000000L};  
        nanosleep(&ts, NULL);
    }
  
    print_progress_bars();
    printf("\n");

   
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    clock_t par_end  = clock();
    double  par_time = (double)(par_end - par_start) / CLOCKS_PER_SEC;

    printf("\n[Main] All threads finished in %.4f seconds.\n", par_time);

   
    pthread_mutex_destroy(&stats_mutex);
    sem_destroy(&disk_semaphore);

    export_report(seq_time, par_time);


    printf("\n========== FINAL RESULTS ==========\n");
    printf("  Total lines  : %ld\n", global_stats.total_lines);
    printf("  INFO         : %ld\n", global_stats.info_count);
    printf("  WARNING      : %ld\n", global_stats.warning_count);
    printf("  ERROR        : %ld\n", global_stats.error_count);
    printf("  CRITICAL     : %ld\n", global_stats.critical_count);
    printf("  Speedup      : %.2fx\n", seq_time / par_time);
    printf("====================================\n");

    return 0;

}
