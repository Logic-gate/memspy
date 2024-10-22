#include "memory_reader.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void read_memory(pid_t pid, unsigned long addr, size_t length, int decode_ascii, int verbose) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach failed");
        return;
    }
    waitpid(pid, NULL, 0);

    unsigned char *buffer = malloc(length);
    if (!buffer) {
        perror("Memory allocation failed");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    printf("Reading memory from address 0x%lx (length: %zu bytes)\n", addr, length);

    for (size_t i = 0; i < length; i += sizeof(long)) {
        long data = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
        if (errno != 0) {
            perror("ptrace peekdata failed");
            free(buffer);
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return;
        }
        memcpy(buffer + i, &data, sizeof(long));
    }

    if (decode_ascii) {
        printf("Decoded ASCII data:\n");
        for (size_t i = 0; i < length; i++) {
            unsigned char byte = buffer[i];
            if (byte >= 32 && byte <= 126) {
                printf("%c", byte);
            } else {
                printf(".");
            }
        }
        printf("\n");
    } else {
        printf("Raw memory (hexadecimal):\n");
        for (size_t i = 0; i < length; i++) {
            printf("%02x ", buffer[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n");
    }

    if (verbose) {
        printf("Memory dump completed.\n");
    }

    free(buffer);

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace detach failed");
    }
}
