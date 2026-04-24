#!/bin/bash
# Sequential driver for every test_nat_*.sh. Each test tears down its
# compose stack before the next starts, so subnet/project isolation is
# clean. Prints a table at the end. Compatible with macOS bash 3.2.
set -u

cd "$(dirname "$0")" || exit 1

TESTS=(
    test_nat_restricted_cone.sh
    test_nat_symmetric.sh
    test_nat_full_cone.sh
    test_nat_address_restricted.sh
    test_nat_hairpin.sh
    test_nat_cgn.sh
    test_nat_udp_blocked.sh
    test_nat_egress_443_only.sh
    test_nat_stateful_firewall.sh
    test_nat_conntrack_timeout.sh
    test_nat_plus_loss.sh
    test_nat_plus_latency.sh
    test_nat_plus_reorder.sh
    test_nat_plus_mtu.sh
    test_nat_plus_bandwidth.sh
    test_nat_dual_symmetric.sh
    test_nat_multihomed.sh
    test_nat_asymmetric_routing.sh
    test_nat_rendezvous_natted.sh
    test_nat_partition_post_reg.sh
    test_nat_ipv6_only.sh
)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p /tmp/nat_logs
RESULTS=()

START_ALL=$(date +%s)
for t in "${TESTS[@]}"; do
    printf "\n${YELLOW}=== %s ===${NC}\n" "$t"
    START=$(date +%s)
    if [ ! -x "./$t" ]; then
        echo "missing or non-executable: $t"
        RESULTS+=("${t}|MISSING|0")
        continue
    fi
    if timeout 600 "./$t" >"/tmp/nat_logs/${t%.sh}.log" 2>&1; then
        RC=0
    else
        RC=$?
    fi
    DUR=$(( $(date +%s) - START ))
    tail -6 "/tmp/nat_logs/${t%.sh}.log"
    case $RC in
        0)   RESULTS+=("${t}|PASS|${DUR}") ;;
        124) RESULTS+=("${t}|TIMEOUT|${DUR}") ;;
        *)   RESULTS+=("${t}|FAIL(rc=${RC})|${DUR}") ;;
    esac
done
TOTAL=$(( $(date +%s) - START_ALL ))

printf "\n\n${YELLOW}============================================${NC}\n"
printf "${YELLOW}NAT traversal suite results (total %ds)${NC}\n" "$TOTAL"
printf "${YELLOW}============================================${NC}\n"
ANY_FAIL=0
for row in "${RESULTS[@]}"; do
    name="${row%%|*}"
    rest="${row#*|}"
    status="${rest%%|*}"
    dur="${rest##*|}"
    case "$status" in
        PASS)    color="$GREEN" ;;
        *)       color="$RED"; ANY_FAIL=1 ;;
    esac
    printf "  %-40s  ${color}%-12s${NC}  %4ds\n" "$name" "$status" "$dur"
done

exit $ANY_FAIL
