#!/bin/bash
set -euo pipefail

PID_FILE=/run/oversip.pid

OVERSIP=$(which oversip)

oversip -P "$PID_FILE"

echo "Waiting on process to exit ($PID_FILE)"

while [ 1 ]; do
    sleep 1
    pid=$(cat "$PID_FILE" || true)
    if [ -z "$pid" ]; then
        echo "No PID found at $PID_FILE; exiting"
        exit
    fi

    echo "Waiting on process $pid"
    while [ -d "/proc/$pid" ]; do
        sleep 1
    done
    echo "Process exited"
done
