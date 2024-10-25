#include "memory_dump.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>


void memory_dump(pid_t pid, unsigned long start_addr, unsigned long end_addr, size_t length, int decode_ascii, int combine_mode) {
    char dump_filename[256];
    FILE *dump_file = NULL;
    unsigned long current_addr = start_addr;

    // single address
    if (end_addr == 0) {
        snprintf(dump_filename, sizeof(dump_filename), "0x%lx_mem.dump", start_addr);
        dump_file = fopen(dump_filename, "w");
        if (!dump_file) {
            perror("Failed to create dump file");
            return;
        }
        dump_memory_region(pid, start_addr, length, decode_ascii, dump_file);
        fclose(dump_file);
        printf("Memory dump written to %s\n", dump_filename);
        return;
    }

    // memory range
    snprintf(dump_filename, sizeof(dump_filename), "0x%lx-0x%lx_mem-range.dump", start_addr, end_addr);
    dump_file = fopen(dump_filename, "w");
    if (!dump_file) {
        perror("Failed to create dump file");
        return;
    }

    //  Memory range iterate
    while (current_addr < end_addr) {
        if (!combine_mode) {
            // Write separator between chunks if not in combine mode
            fprintf(dump_file, "-------0x%lx-------\n", current_addr); // Usefull for regex. Add to config in later version
        }
        size_t remaining_bytes = end_addr - current_addr;
        size_t bytes_to_read = (remaining_bytes > length) ? length : remaining_bytes;
        dump_memory_region(pid, current_addr, bytes_to_read, decode_ascii, dump_file);
        current_addr += bytes_to_read;  // next chunk
    }

    fclose(dump_file);
    printf("Memory dump written to %s\n", dump_filename);
}

void dump_memory_region(pid_t pid, unsigned long addr, size_t length, int decode_ascii, FILE *dump_file) {
    unsigned char *buffer = malloc(length);  // This will allocate memory to hold the entire dump. Add better error handleing
    if (!buffer) {
        perror("Memory allocation failed");
        return;
    }

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach failed");
        free(buffer);
        return;
    }
    waitpid(pid, NULL, 0);

    // Data in chunks
    for (size_t i = 0; i < length; i += sizeof(long)) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
        if (errno != 0) {
            perror("ptrace peekdata failed");
            break;
        }
        size_t bytes_to_copy = (length - i >= sizeof(long)) ? sizeof(long) : length - i;
        memcpy(buffer + i, &data, bytes_to_copy);
    }

    // Output the memory dump to the file
    if (decode_ascii) {
        for (size_t i = 0; i < length; i++) {
            unsigned char byte = buffer[i];
            if (byte >= 32 && byte <= 126) {
                fprintf(dump_file, "%c", byte);  // ASCII
            } else {
                fprintf(dump_file, ".");  
            }
        }
    } else {
        for (size_t i = 0; i < length; i++) {
            fprintf(dump_file, "%02x ", buffer[i]); 
        }
    }

    fprintf(dump_file, "\n");

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace detach failed");
    }

    free(buffer);
}
