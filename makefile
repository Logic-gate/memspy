CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lrt

TARGET = memspy
SRCS = src/main.c src/memory_injector.c src/memory_reader.c
OBJS = $(SRCS:.c=.o)


all: $(TARGET)

# Compile the program
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

clean:
	@echo "Cleaning up..."
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
