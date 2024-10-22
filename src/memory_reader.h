#ifndef MEMORY_READER_H
#define MEMORY_READER_H

#include <sys/types.h>

void read_memory(pid_t pid, unsigned long addr, size_t length, int decode_ascii, int verbose);

#endif  // MEMORY_READER_H
