#!/bin/bash

# Basic Unit Test for memory_injector
# Ensure a valid PID is provided for testing.
# Usage: sudo ./run_unit_tests.sh <pid>

if [ -z "$1" ]; then
    echo "Error: No PID provided."
    echo "Usage: sudo $0 <pid>"
    exit 1
fi

# Assign provided PID to variable
PID=$1
LOG_DIR=$(pwd)  # The directory where the script is run
INJECT_VALUE=123456
INJECT_STRING="hello_world"
SINGLE_MEM_ADDR="0x55e87d26e000"  # Use this for --read, --realtime
MEM_RANGE="0x55e87d26e000-0x55e87d26e000"  # Use this range for --inject, --monitor, etc.
MEM_LENGTH=64  # Number of bytes to read
RESULT=0
TIMEOUT=5  # Timeout for long-running tests (in seconds)
TEMP_OUTPUT_FILE="/tmp/realtime_output_$$.log"  # Temporary file for realtime output

# Helper function to locate the latest log file created
find_latest_log() {
    # Find the most recent log file matching <pid>_<timestamp>.log pattern in the current directory
    LOG_FILE=$(ls -t ${LOG_DIR}/${PID}_*.log 2>/dev/null | head -n 1)
    if [ -z "$LOG_FILE" ]; then
        echo "Error: No log file found for PID $PID in $LOG_DIR"
        return 1
    fi
    return 0
}

# Helper function to check test results
check_result() {
    if [ $? -eq 0 ]; then
        echo "[PASS] $1"
    else
        echo "[FAIL] $1"
        RESULT=1
    fi
}

# Test --inject with integer value (uses an address range)
echo "Running --inject test..."
sudo ./memory_injector $PID $MEM_RANGE --inject $INJECT_VALUE --log
sleep 1  # Give some time for the log file to be created
find_latest_log || exit 1
check_result "--inject integer value into memory"

# Test --inject-string (uses an address range)
echo "Running --inject-string test..."
sudo ./memory_injector $PID $MEM_RANGE --inject-string $INJECT_STRING --log
sleep 1
find_latest_log || exit 1
check_result "--inject-string value into memory"

# Test --read with a single memory address
echo "Running --read test..."
sudo ./memory_injector $PID $SINGLE_MEM_ADDR --read $MEM_LENGTH --log
sleep 1
find_latest_log || exit 1
check_result "--read memory"

# Test --realtime with a single memory address and specified length in ASCII format
echo "Running --realtime test (timed)..."
timeout $TIMEOUT sudo ./memory_injector $PID $SINGLE_MEM_ADDR --realtime --length $MEM_LENGTH --ascii > "$TEMP_OUTPUT_FILE" 2>&1
if grep -q "New ASCII data:" "$TEMP_OUTPUT_FILE"; then
    echo "[PASS] --realtime monitoring with ASCII output"
else
    echo "[FAIL] --realtime monitoring with ASCII output"
    echo "Realtime Output:"
    cat "$TEMP_OUTPUT_FILE"  # Display the output for debugging
    RESULT=1
fi
rm -f "$TEMP_OUTPUT_FILE"  # Clean up the temporary file

# Test --monitor on a memory range
echo "Running --monitor test (timed)..."
sudo ./memory_injector $PID $MEM_RANGE --monitor --log &  # Run in background
MONITOR_PID=$!  # Capture process ID
sleep $TIMEOUT  # Let it run for the specified duration
sudo kill $MONITOR_PID  # Terminate the process
find_latest_log || exit 1
if grep -q "CHANGE" $LOG_FILE; then
    echo "[PASS] --monitor a memory address for changes"
else
    echo "[FAIL] --monitor a memory address for changes"
    RESULT=1
fi

# Test --spy mode
echo "Running --spy test (timed)..."
sudo ./memory_injector $PID --spy --log &  # Run in background
SPY_PID=$!  # Capture process ID
sleep $TIMEOUT  # Let it run for the specified duration
sudo kill $SPY_PID  # Terminate the process
find_latest_log || exit 1
if grep -q "SPY" $LOG_FILE; then
    echo "[PASS] --spy mode"
else
    echo "[FAIL] --spy mode"
    RESULT=1
fi

# Check if log file was found and contains expected content
if [ -f "$LOG_FILE" ]; then
    echo "[PASS] Log file created: $LOG_FILE"
else
    echo "[FAIL] Log file not created."
    RESULT=1
fi

# Validate log for expected content
if grep -E -q "INJECT|SPY|CHANGE|Change detected" "$LOG_FILE"; then
    echo "[PASS] Log contains expected test results (INJECT, CHANGE, SPY)."
else
    echo "[FAIL] Log does not contain expected test results."
    echo "Log contents:"
    cat "$LOG_FILE"  # Display the log contents for debugging
    RESULT=1
fi

# Final result
if [ $RESULT -eq 0 ]; then
    echo "All tests passed!"
else
    echo "Some tests failed."
fi

exit $RESULT
