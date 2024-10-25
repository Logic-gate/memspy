#include "memory_injector.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char* get_timestamp() {
    static char timestamp[BUFFER_SIZE];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(timestamp, BUFFER_SIZE, "[%04d-%02d-%02d %02d:%02d:%02d]",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);
    return timestamp;
}

void log_message(const char *log_file, const char *message) {
    FILE *log_fp = fopen(log_file, "a");
    if (log_fp) {
        fprintf(log_fp, "%s %s\n", get_timestamp(), message);
        fclose(log_fp);
    }
}

void generate_log_filename(char *filename, pid_t pid) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(filename, BUFFER_SIZE, "%d_%04d-%02d-%02d_%02d-%02d-%02d.log", pid, 
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, 
             t->tm_hour, t->tm_min, t->tm_sec);
}

// Inject int to a mem addr
void inject_value(pid_t pid, unsigned long addr, long value, const char *log_file, int verbose) {
    char log_msg[BUFFER_SIZE];

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror(COLOR_RED "ptrace attach failed" COLOR_RESET);
        return;
    }
    waitpid(pid, NULL, 0);

    long original_value = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (errno != 0) {
        perror(COLOR_RED "ptrace peekdata failed" COLOR_RESET);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)value) == -1) {
        perror(COLOR_RED "ptrace pokedata failed" COLOR_RESET);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    snprintf(log_msg, BUFFER_SIZE, "[INJECT] Successfully injected value %ld at address 0x%lx", value, addr);
    if (log_file) log_message(log_file, log_msg);
    printf("%s " COLOR_GREEN "[INJECT] Successfully injected value %ld at address " COLOR_CYAN "0x%lx\n" COLOR_RESET, get_timestamp(), value, addr);

    if (verbose) {
        snprintf(log_msg, BUFFER_SIZE, "[INJECT] Original value at 0x%lx: %ld -> Injected: %ld", addr, original_value, value);
        if (log_file) log_message(log_file, log_msg);
        printf("%s " COLOR_YELLOW "[INJECT] Original value at " COLOR_CYAN "0x%lx" COLOR_RESET ": %ld -> Injected: %ld\n", get_timestamp(), addr, original_value, value);
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror(COLOR_RED "ptrace detach failed" COLOR_RESET);
    }
}

// Inject str to a mem addr
void inject_string_value(pid_t pid, unsigned long addr, const char *str, const char *log_file, int verbose) {
    size_t len = strlen(str) + 1;  // +1 for the null terminator
    char log_msg[BUFFER_SIZE];

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror(COLOR_RED "ptrace attach failed" COLOR_RESET);
        return;
    }
    waitpid(pid, NULL, 0);

    for (size_t i = 0; i < len; i += sizeof(long)) {
        long data = 0;
        memcpy(&data, str + i, sizeof(long));
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i), (void *)data) == -1) {
            perror(COLOR_RED "ptrace pokedata failed" COLOR_RESET);
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return;
        }
    }

    snprintf(log_msg, BUFFER_SIZE, "[INJECT] Successfully injected string \"%s\" at address 0x%lx", str, addr);
    if (log_file) log_message(log_file, log_msg);
    printf("%s " COLOR_GREEN "[INJECT] Successfully injected string \"%s\" at address " COLOR_CYAN "0x%lx\n" COLOR_RESET, get_timestamp(), str, addr);

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror(COLOR_RED "ptrace detach failed" COLOR_RESET);
    }
}

// Realtime memory monitoring for a single address with user-provided length
void monitor_memory_realtime(pid_t pid, unsigned long addr, size_t length, int decode_ascii, const char *log_file, int verbose) {
    // Ensure BUFFER_SIZE is large enough to handle logs for long memory reads
    char log_msg[BUFFER_SIZE * 2];  // Buffer large enough to store log messages for larger memory regions
    unsigned char *previous_data = malloc(length);
    unsigned char *current_data = malloc(length);

    if (!previous_data || !current_data) {
        perror(COLOR_RED "Memory allocation failed" COLOR_RESET);
        return;
    }

    // Correct log message: display the actual length provided by the user
    printf("%s " COLOR_GREEN "[INFO] Real-time monitoring memory at address: 0x%lx with length %zu bytes\n" COLOR_RESET, get_timestamp(), addr, length);

    // Initialize previous_data with current memory content to avoid false positives
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror(COLOR_RED "ptrace attach failed" COLOR_RESET);
        free(previous_data);
        free(current_data);
        return;
    }
    waitpid(pid, NULL, 0);

    for (size_t i = 0; i < length; i += sizeof(long)) {
        long data = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
        if (errno != 0) {
            perror(COLOR_RED "ptrace peekdata failed" COLOR_RESET);
            break;
        }
        memcpy(previous_data + i, &data, sizeof(long));
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror(COLOR_RED "ptrace detach failed" COLOR_RESET);
        free(previous_data);
        free(current_data);
        return;
    }

    // Monitoring loop
    while (1) {
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
            perror(COLOR_RED "ptrace attach failed" COLOR_RESET);
            free(previous_data);
            free(current_data);
            return;
        }
        waitpid(pid, NULL, 0);

        // Read the memory block in chunks of sizeof(long)
        for (size_t i = 0; i < length; i += sizeof(long)) {
            long data = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
            if (errno != 0) {
                perror(COLOR_RED "ptrace peekdata failed" COLOR_RESET);
                break;
            }
            memcpy(current_data + i, &data, sizeof(long));
        }

        // Compare memory
        if (memcmp(current_data, previous_data, length) != 0) {
            snprintf(log_msg, sizeof(log_msg), "[REALTIME] Change detected at 0x%lx", addr);
            if (log_file) log_message(log_file, log_msg);

            printf("%s " COLOR_YELLOW "[CHANGE] Memory at " COLOR_CYAN "0x%lx" COLOR_RESET " has changed\n", get_timestamp(), addr);
            
            // Output the new memory content
            if (decode_ascii) {
                printf(COLOR_MAGENTA "New ASCII data: ");
                for (size_t i = 0; i < length; i++) {
                    unsigned char byte = current_data[i];
                    if (byte >= 32 && byte <= 126) {
                        printf("%c", byte);  // Printable ASCII
                    } else {
                        printf(".");  // Non-printable bytes
                    }
                }
                printf(COLOR_RESET "\n");
            } else {
                printf(COLOR_GREEN "New Hex data: ");
                for (size_t i = 0; i < length; i++) {
                    printf("%02x ", current_data[i]);  // Print byte in hex
                }
                printf(COLOR_RESET "\n");
            }

            // Update previous_data with the new values
            memcpy(previous_data, current_data, length);
        }

        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
            perror(COLOR_RED "ptrace detach failed" COLOR_RESET);
            free(previous_data);
            free(current_data);
            return;
        }

        sleep(1);  // Sleep for 1 second before checking again
    }

    free(previous_data);
    free(current_data);
}



// Monitor a memory range in real-time
void monitor_memory_range(pid_t pid, unsigned long start_addr, unsigned long end_addr, const char *log_file, int verbose) {
    char log_msg[BUFFER_SIZE];
    long *previous_values = malloc((end_addr - start_addr) * sizeof(long));
    long *current_values = malloc((end_addr - start_addr) * sizeof(long));

    if (!previous_values || !current_values) {
        perror(COLOR_RED "Failed to allocate memory for monitoring" COLOR_RESET);
        return;
    }

    printf("%s " COLOR_GREEN "[INFO] Monitoring memory range: 0x%lx - 0x%lx\n" COLOR_RESET, get_timestamp(), start_addr, end_addr);

    while (1) {
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
            perror(COLOR_RED "ptrace attach failed" COLOR_RESET);
            free(previous_values);
            free(current_values);
            return;
        }
        waitpid(pid, NULL, 0);

        for (unsigned long addr = start_addr; addr < end_addr; addr += sizeof(long)) {
            unsigned long index = (addr - start_addr) / sizeof(long);

            current_values[index] = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
            if (errno != 0) {
                continue;  
            }

            if (current_values[index] != previous_values[index]) {
                snprintf(log_msg, BUFFER_SIZE, "[MONITOR] Value change at address 0x%lx: %ld -> %ld", addr, previous_values[index], current_values[index]);
                if (log_file) log_message(log_file, log_msg);

                printf("%s " COLOR_YELLOW "[CHANGE] Value changed at address " COLOR_CYAN "0x%lx" COLOR_RESET ": " COLOR_MAGENTA "%ld" COLOR_RESET " -> " COLOR_GREEN "%ld\n" COLOR_RESET,
                       get_timestamp(), addr, previous_values[index], current_values[index]);

                previous_values[index] = current_values[index];
            }
        }

        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
            perror(COLOR_RED "ptrace detach failed" COLOR_RESET);
            free(previous_values);
            free(current_values);
            return;
        }

        sleep(1);
    }

    free(previous_values);
    free(current_values);
}

// Spy mode: monitor all memory regions and show actual changes. This will cause pid source to be unresponsive
void monitor_all_memory_with_changes(pid_t pid, const char *log_file, int verbose) {
    char maps_file[BUFFER_SIZE];
    char log_msg[BUFFER_SIZE];
    snprintf(maps_file, BUFFER_SIZE, "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_file, "r");
    if (!fp) {
        perror(COLOR_RED "Failed to open memory map file" COLOR_RESET);
        return;
    }

    printf("%s " COLOR_GREEN "[INFO] Monitoring all memory regions for PID %d\n" COLOR_RESET, get_timestamp(), pid);

    unsigned char *previous_data = NULL;
    unsigned char *current_data = NULL;
    size_t region_size = 0;

    while (1) {
        rewind(fp);

        char line[BUFFER_SIZE];
        while (fgets(line, sizeof(line), fp)) {
            unsigned long start_addr, end_addr;
            char perms[5];
            if (sscanf(line, "%lx-%lx %s", &start_addr, &end_addr, perms) >= 3) {
                if (perms[0] != 'r') continue;  // readable regions

                region_size = end_addr - start_addr;
                previous_data = malloc(region_size);
                current_data = malloc(region_size);
                if (!previous_data || !current_data) {
                    perror(COLOR_RED "Memory allocation failed" COLOR_RESET);
                    break;
                }

                printf("%s " COLOR_CYAN "[SPY] Monitoring " COLOR_GREEN "0x%lx" COLOR_RESET "-" COLOR_GREEN "0x%lx" COLOR_RESET "\n", get_timestamp(), start_addr, end_addr);

                // Attach to the process and read memory...thank you some guy on stackoverflow
                if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
                    perror(COLOR_RED "ptrace attach failed" COLOR_RESET);
                    free(previous_data);
                    free(current_data);
                    return;
                }
                waitpid(pid, NULL, 0);

                for (unsigned long addr = start_addr; addr < end_addr; addr += sizeof(long)) {
                    unsigned long index = addr - start_addr;
                    long data = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
                    if (errno != 0) {
                        continue;  // This is ugly...change later
                    }
                    memcpy(current_data + index, &data, sizeof(long));
                }

                if (previous_data && memcmp(current_data, previous_data, region_size) != 0) {
                    snprintf(log_msg, BUFFER_SIZE, "[SPY] Change detected in region 0x%lx-0x%lx", start_addr, end_addr);
                    if (log_file) log_message(log_file, log_msg);

                    printf("%s " COLOR_YELLOW "[CHANGE] Memory region " COLOR_CYAN "0x%lx" COLOR_RESET "-" COLOR_CYAN "0x%lx" COLOR_RESET " has changed\n", get_timestamp(), start_addr, end_addr);
                }

                // Detach
                if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
                    perror(COLOR_RED "ptrace detach failed" COLOR_RESET);
                    free(previous_data);
                    free(current_data);
                    return;
                }

                memcpy(previous_data, current_data, region_size);
            }
        }

        sleep(1); 
    }

    free(previous_data);
    free(current_data);
    fclose(fp);
}

// Monitor a single memory address for changes in real-time
void monitor_memory_single(pid_t pid, unsigned long addr, const char *log_file, int verbose) {
    char log_msg[BUFFER_SIZE];
    long previous_value = 0;
    long current_value = 0;

    printf("%s " COLOR_GREEN "[INFO] Monitoring memory address: 0x%lx\n" COLOR_RESET, get_timestamp(), addr);

    while (1) {
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
            perror(COLOR_RED "ptrace attach failed" COLOR_RESET);
            return;
        }
        waitpid(pid, NULL, 0);

        current_value = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
        if (errno != 0) {
            perror(COLOR_RED "ptrace peekdata failed" COLOR_RESET);
            break;
        }

        if (current_value != previous_value) {
            snprintf(log_msg, BUFFER_SIZE, "[MONITOR] Value change at address 0x%lx: %ld -> %ld", addr, previous_value, current_value);
            if (log_file) log_message(log_file, log_msg);

            printf("%s " COLOR_YELLOW "[CHANGE] Value changed at address " COLOR_CYAN "0x%lx" COLOR_RESET ": " COLOR_MAGENTA "%ld" COLOR_RESET " -> " COLOR_GREEN "%ld\n" COLOR_RESET,
                   get_timestamp(), addr, previous_value, current_value);

            previous_value = current_value;
        }

        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
            perror(COLOR_RED "ptrace detach failed" COLOR_RESET);
            return;
        }

        sleep(1); 
    }
}


// Print memmap of a given process (from /proc/<pid>/maps)
void print_memory_map(pid_t pid) {
    char maps_file[BUFFER_SIZE];
    snprintf(maps_file, BUFFER_SIZE, "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_file, "r");
    if (!fp) {
        perror(COLOR_RED "Failed to open memory map file" COLOR_RESET);
        return;
    }

    printf("%s " COLOR_GREEN "Memory regions for PID %d:\n" COLOR_RESET, get_timestamp(), pid);
    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start_addr, end_addr;
        char perms[5];  // Permissions: r, w, x, p
        unsigned long offset;
        int dev_major, dev_minor;
        unsigned long inode;
        char pathname[BUFFER_SIZE] = "";

       
        if (sscanf(line, "%lx-%lx %s %lx %x:%x %lu %s",
                   &start_addr, &end_addr, perms, &offset, &dev_major, &dev_minor, &inode, pathname) >= 7) {
            unsigned long region_size = end_addr - start_addr;

            
            printf(COLOR_CYAN "0x%lx" COLOR_RESET "-" COLOR_CYAN "0x%lx" COLOR_RESET
                   " (" COLOR_YELLOW "%lu bytes" COLOR_RESET ") "
                   COLOR_GREEN "%s" COLOR_RESET " "
                   COLOR_MAGENTA "%s" COLOR_RESET "\n",
                   start_addr, end_addr, region_size, perms, pathname[0] ? pathname : "[anonymous]");
        }
    }

    fclose(fp);
}
