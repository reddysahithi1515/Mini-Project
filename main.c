#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PROCESSES 1000
#define MAX_NAME 256

// Structure to store process info
typedef struct {
    int pid;
    int ppid;
    char name[MAX_NAME];
    char path[MAX_NAME];
    int suspicious_score;
} Process;

// Global array to store all processes
Process process_list[MAX_PROCESSES];
int process_count = 0;

// Function to load processes from CSV (Sysmon logs exported as CSV)
void load_processes(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Error opening file %s\n", filename);
        exit(1);
    }

    char line[1024];
    // Skip header
    fgets(line, sizeof(line), file);

    while (fgets(line, sizeof(line), file)) {
        if (process_count >= MAX_PROCESSES) break;

        // CSV format: PID,PPID,ProcessName,Path
        char *token = strtok(line, ",");
        process_list[process_count].pid = atoi(token);

        token = strtok(NULL, ",");
        process_list[process_count].ppid = atoi(token);

        token = strtok(NULL, ",");
        strcpy(process_list[process_count].name, token);

        token = strtok(NULL, ",\n");
        strcpy(process_list[process_count].path, token);

        process_list[process_count].suspicious_score = 0;

        process_count++;
    }

    fclose(file);
}

// Heuristics function
void apply_heuristics() {
    for (int i = 0; i < process_count; i++) {
        // Rule 1: Process running from temp folder
        if (strstr(process_list[i].path, "Temp") != NULL ||
            strstr(process_list[i].path, "temp") != NULL) {
            process_list[i].suspicious_score += 3;
        }

        // Rule 2: Suspicious parent (example: notepad spawning powershell)
        for (int j = 0; j < process_count; j++) {
            if (process_list[i].ppid == process_list[j].pid) {
                if (strcmp(process_list[i].name, "powershell.exe") == 0 &&
                    strcmp(process_list[j].name, "notepad.exe") == 0) {
                    process_list[i].suspicious_score += 3;
                }
            }
        }

        // Rule 3: Suspicious process name (example)
        if (strstr(process_list[i].name, "evil") != NULL) {
            process_list[i].suspicious_score += 4;
        }
    }
}

// Function to print report
void print_report() {
    printf("\nSuspicious Process Report:\n");
    printf("PID\tPPID\tProcessName\tSuspiciousScore\tStatus\n");
    printf("--------------------------------------------------------\n");

    for (int i = 0; i < process_count; i++) {
        printf("%d\t%d\t%s\t%d\t\t%s\n",
               process_list[i].pid,
               process_list[i].ppid,
               process_list[i].name,
               process_list[i].suspicious_score,
               (process_list[i].suspicious_score >= 3) ? "Suspicious" : "Normal");
    }
}

int main() {
    // Step 1: Load Sysmon CSV log
    load_processes("sysmon_process_log.csv");

    // Step 2: Apply heuristics
    apply_heuristics();

    // Step 3: Print report
    print_report();

    return 0;
}
