#include "memory_injector.h"
#include "memory_reader.h"
#include <stdlib.h> 
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>

void print_help() {
    printf(COLOR_GREEN "Usage:\n" COLOR_RESET);
    printf(COLOR_CYAN "  ./memspy <pid> [options]\n" COLOR_RESET);
    
    printf(COLOR_GREEN "\nOptions:\n" COLOR_RESET);
    printf(COLOR_YELLOW "  --monitor        " COLOR_RESET "Monitor the memory address or range for changes in real-time.\n");
    printf(COLOR_YELLOW "  --inject <value> " COLOR_RESET "Inject an integer value into the specified memory address.\n");
    printf(COLOR_YELLOW "  --inject-string <string> " COLOR_RESET "Inject a string into the specified memory address.\n");
    printf(COLOR_YELLOW "  --read <length>  " COLOR_RESET "Read memory from the specified address (in bytes). Default is 64 bytes.\n");
    printf(COLOR_YELLOW "  --realtime       " COLOR_RESET "Enable real-time memory reading to continuously detect and print memory changes.\n");
    printf(COLOR_YELLOW "  --ascii          " COLOR_RESET "Decode memory as ASCII when using --read or --realtime. Default is hexadecimal.\n");
    printf(COLOR_YELLOW "  --spy            " COLOR_RESET "Monitor all readable memory regions for changes.\n");
    printf(COLOR_YELLOW "  --log            " COLOR_RESET "Enable logging. If no file is specified, it will create a log file.\n");
    printf(COLOR_YELLOW "  --verbose        " COLOR_RESET "Enable detailed logging for memory changes, injection, or reading.\n");
    printf(COLOR_YELLOW "  --help           " COLOR_RESET "Show this help message.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2 || (argc > 1 && strcmp(argv[1], "--help") == 0)) {
        print_help();
        return 0;
    }

    pid_t pid = atoi(argv[1]);

    int verbose = 0;
    int monitor = 0;
    int inject_mode = 0;
    int inject_string_mode = 0;
    int read_memory_mode = 0;
    int decode_ascii = 0;
    int realtime_mode = 0;
    int log_enabled = 0;
    int spy_mode = 0;
    long inject_value_data = 0;
    size_t length = 64;  // Default mem length
    char *inject_string = NULL;
    char log_file[256] = {0};

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        }
        if (strcmp(argv[i], "--monitor") == 0) {
            monitor = 1;
        }
        if (strcmp(argv[i], "--inject") == 0) {
            if (i + 1 < argc) {
                inject_value_data = atol(argv[++i]);
                inject_mode = 1;
            } else {
                fprintf(stderr, COLOR_RED "Error: --inject requires a value argument\n" COLOR_RESET);
                return 1;
            }
        }
        if (strcmp(argv[i], "--inject-string") == 0) {
            if (i + 1 < argc) {
                inject_string = argv[++i];
                inject_string_mode = 1;
            } else {
                fprintf(stderr, COLOR_RED "Error: --inject-string requires a string argument\n" COLOR_RESET);
                return 1;
            }
        }
        if (strcmp(argv[i], "--read") == 0) {
            read_memory_mode = 1;
            if (i + 1 < argc) {
                length = atol(argv[++i]);
            }
        }
        if (strcmp(argv[i], "--realtime") == 0) {
            realtime_mode = 1;
        }
        if (strcmp(argv[i], "--ascii") == 0) {
            decode_ascii = 1;
        }
        if (strcmp(argv[i], "--log") == 0) {
            log_enabled = 1;
        }
        if (strcmp(argv[i], "--spy") == 0) {
            spy_mode = 1;
        }
    }

    if (!monitor && !inject_mode && !inject_string_mode && !spy_mode && !read_memory_mode && !realtime_mode) {
        print_memory_map(pid);
        return 0;
    }

    if (log_enabled) {
        generate_log_filename(log_file, pid);
    }

    if (read_memory_mode || realtime_mode) {
        unsigned long addr = 0;
        if (argc > 2 && sscanf(argv[2], "%lx", &addr) == 1) {
            if (realtime_mode) {
                monitor_memory_realtime(pid, addr, length, decode_ascii, log_enabled ? log_file : NULL, verbose);
            } else {
                read_memory(pid, addr, length, decode_ascii, verbose);
            }
            return 0;
        } else {
            fprintf(stderr, COLOR_RED "Error: Invalid address format for --read or --realtime.\n" COLOR_RESET);
            return 1;
        }
    }

    if (spy_mode) {
        monitor_all_memory_with_changes(pid, log_enabled ? log_file : NULL, verbose);
        return 0;
    }

    if (monitor || inject_mode || inject_string_mode) {
        if (argc > 2 && strstr(argv[2], "-")) {
            unsigned long start_addr = 0, end_addr = 0;
            char *range_str = argv[2];
            if (sscanf(range_str, "%lx-%lx", &start_addr, &end_addr) != 2) {
                fprintf(stderr, COLOR_RED "Invalid address range format. Expected format: <start_address-end_address>\n" COLOR_RESET);
                return 1;
            }

            if (inject_mode) {
                if (start_addr == end_addr) {
                    inject_value(pid, start_addr, inject_value_data, log_enabled ? log_file : NULL, verbose);
                } else {
                    fprintf(stderr, COLOR_RED "Error: --inject can only be used with a single memory address.\n" COLOR_RESET);
                }
            } else if (inject_string_mode) {
                if (start_addr == end_addr) {
                    inject_string_value(pid, start_addr, inject_string, log_enabled ? log_file : NULL, verbose);
                } else {
                    fprintf(stderr, COLOR_RED "Error: --inject-string can only be used with a single memory address.\n" COLOR_RESET);
                }
            } else if (monitor) {
                if (start_addr == end_addr) {
                    monitor_memory_single(pid, start_addr, log_enabled ? log_file : NULL, verbose);
                } else {
                    monitor_memory_range(pid, start_addr, end_addr, log_enabled ? log_file : NULL, verbose);
                }
            }
        } else {
            fprintf(stderr, COLOR_RED "Error: Address range is required for --monitor, --inject, or --inject-string.\n" COLOR_RESET);
            return 1;
        }
    }

    return 0;
}
