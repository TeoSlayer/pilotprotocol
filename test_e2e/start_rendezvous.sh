#!/bin/bash
# Start the rendezvous server (combined registry + beacon)
cd "$(dirname "$0")/rendezvous"
./rendezvous --config rendezvous.json
