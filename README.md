# Memspy 

**Memspy** is a simple `ptrace` wrapper designed to interact with the memory of running processes. It allows you to inject values (both integers and strings) into specified memory addresses, read from process memory, and monitor memory regions for real-time changes.

## Features

- **Memory Injection**: Inject integer values or strings into specific memory addresses of a running process.
- **Memory Reading**: Read the contents of process memory at specific addresses.
- **Real-Time Monitoring**: Monitor memory regions in real-time and detect changes.
- **Memory Spy**: Spy on all memory regions of a process and log changes across the entire memory map.

## Requirements

This tool uses the `ptrace` system call to interact with process memory, so it requires `sudo` (superuser) access. It is compatible with Linux-based systems.

## Compilation

To compile the program, simply run `make` in the project directory. The binary will be generated in the same directory.

```bash
make
```

## Running the Program

### Basic Usage

```bash
sudo ./memspy <pid> <address-range> [options]
```

### Options:

- `--inject <value>`: Injects an integer value into the specified memory address range.
- `--inject-string <string>`: Injects a string into the specified memory address range.
- `--read <length>`: Reads memory from a specific address and outputs the contents.
- `--monitor`: Monitors a memory range for any changes.
- `--spy`: Spies on all memory regions of the process and logs any changes.
- `--realtime`: Monitors a specific memory address in real-time.
- `--ascii`: Decodes the memory contents into ASCII format (used with `--realtime`).
- `--log`: Automatically creates a log file in the format `<pid>_<timestamp>.log` in the current directory.

### Example Usage

#### Inject an Integer:

```bash
sudo ./memspy 4629 0x7ffea733000-0x7ffea734000 --inject 123456
```

Injects the integer `123456` into the specified memory address range for the process with PID `4629`.

#### Inject a String:

```bash
sudo ./memspy 4629 0x7ffea733000-0x7ffea734000 --inject-string "hello_world"
```

Injects the string `"hello_world"` into the specified memory address range.

#### Read Memory:

```bash
sudo ./memspy 4629 0x7ffea733000 --read 64
```

Reads `64` bytes from the memory at address `0x7ffea733000` for the process with PID `4629`.

#### Monitor Memory in Real-Time:

```bash
sudo ./memspy 4629 0x7ffea733000 --realtime --length 64 --ascii
```

Monitors memory at address `0x7ffea733000` in real-time, reading 64 bytes and decoding them as ASCII.

#### Monitor a Memory Range:

```bash
sudo ./memspy 4629 0x7ffea733000-0x7ffea734000 --monitor
```

Monitors the specified memory range for any changes.

#### Spy on All Memory Regions:

```bash
sudo ./memspy 4629 --spy
```

Monitor all memory regions of the process and logs changes.

## Logs

When the `--log` option is provided, the program generates logs named using the following format:

```
<pid>_<timestamp>.log
```

Logs are stored in the same directory where the program is executed. They contain detailed information about memory changes, injections, and spy mode results.

### Example Log Entry:

```text
[2024-10-22 12:30:59] [INJECT] Successfully injected value 123456 at address 0x7ffea733000
[2024-10-22 12:31:00] [INJECT] Successfully injected string "hello_world" at address 0x7ffea733000
[2024-10-22 12:31:05] [SPY] Monitoring 0x7ffea733000-0x7ffea734000
[2024-10-22 12:31:05] [CHANGE] Memory region 0x7ffea733000-0x7ffea734000 has changed
```

