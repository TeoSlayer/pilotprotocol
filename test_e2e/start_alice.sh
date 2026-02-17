#!/bin/bash
# Start Alice's daemon
cd "$(dirname "$0")/alice"
./daemon --config daemon.json
