#ifndef MEMORY_INJECTOR_H
#define MEMORY_INJECTOR_H

#include <sys/types.h>

#define COLOR_RESET "\x1b[0m"
#define COLOR_CYAN "\x1b[36m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_RED "\x1b[31m"

#define BUFFER_SIZE 256


void inject_value(pid_t pid, unsigned long addr, long value, const char *log_file, int verbose);
void inject_string_value(pid_t pid, unsigned long addr, const char *str, const char *log_file, int verbose);
void monitor_memory_single(pid_t pid, unsigned long addr, const char *log_file, int verbose);
void monitor_memory_range(pid_t pid, unsigned long start_addr, unsigned long end_addr, const char *log_file, int verbose);
void monitor_memory_realtime(pid_t pid, unsigned long addr, size_t length, int decode_ascii, const char *log_file, int verbose);
void monitor_all_memory_with_changes(pid_t pid, const char *log_file, int verbose);
void print_memory_map(pid_t pid);
void log_message(const char *log_file, const char *message);
void generate_log_filename(char *filename, pid_t pid);
char* get_timestamp();


#endif  // MEMORY_INJECTOR_H
