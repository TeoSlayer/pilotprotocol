#!/bin/bash
# Start Bob's daemon
cd "$(dirname "$0")/bob"
./daemon --config daemon.json
