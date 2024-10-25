#ifndef MEMORY_DUMP_H
#define MEMORY_DUMP_H

#include <stdio.h>
#include <sys/types.h>

void memory_dump(pid_t pid, unsigned long start_addr, unsigned long end_addr, size_t length, int decode_ascii, int combine_mode);
void dump_memory_region(pid_t pid, unsigned long addr, size_t length, int decode_ascii, FILE *dump_file);


#endif