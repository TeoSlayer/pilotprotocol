#!/bin/bash
# Helpers for webhook integration tests. Source AFTER setting $DC.
#
# The webhook-sink container is python:3.12-slim and the cold-start HTTP
# bind takes 5-8s after `docker run`, so polling container state ("running")
# is not enough — the sink can be "running" but not yet accepting HTTP.
# Tests that race past readiness see "agents did not register" because
# their agents emit node.registered webhooks to a sink that 502s the post,
# and the daemon's webhook retry budget eats time the registration probe
# was supposed to use.

# ensure_webhook_sink_ready brings up rendezvous + webhook-sink, then waits
# until the sink is BOTH "running" AND its healthcheck has gone "healthy"
# (HTTP-bound, accepting POSTs). Logs diagnostic state on failure so the
# next maintainer doesn't have to guess.
#
# Returns 0 on ready, 1 on timeout (caller decides whether to log_fail).
# Honors PILOT_TEST_WAIT_MULT for parallel-suite slowdown.
ensure_webhook_sink_ready() {
    local mult="${PILOT_TEST_WAIT_MULT:-1}"
    local total_attempts=$((45 * mult))

    $DC up -d rendezvous webhook-sink >/dev/null 2>&1

    for _ in $(seq 1 "$total_attempts"); do
        # Container running AND health=healthy (the compose healthcheck pings
        # the python HTTP server itself, so this is a true end-to-end ready).
        STATE=$($DC ps --format '{{.Service}}\t{{.State}}\t{{.Health}}' 2>/dev/null | \
            awk -F'\t' '$1=="webhook-sink"{print $2"|"$3}')
        case "$STATE" in
            running\|healthy) return 0 ;;
            running\|) # no healthcheck reported yet; HTTP-probe directly.
                if $DC exec -T webhook-sink sh -c \
                    'python3 -c "import urllib.request; urllib.request.urlopen(\"http://127.0.0.1:18080/\").read()" 2>/dev/null'; then
                    return 0
                fi
                ;;
        esac
        sleep 1
    done

    # Diagnostic dump on timeout — saves a guessing round-trip.
    echo "ensure_webhook_sink_ready: timeout — diagnostic state follows" >&2
    $DC ps 2>&1 | head -10 >&2
    $DC logs --tail=20 webhook-sink 2>&1 >&2
    return 1
}
