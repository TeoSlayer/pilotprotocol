#!/bin/bash
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}=== Event Stream Service Demo ===${NC}\n"

if ! pilotctl --json daemon status --check 2>/dev/null; then
    pilotctl daemon start
fi

OUR_INFO=$(pilotctl --json info)
OUR_HOSTNAME=$(echo "$OUR_INFO" | jq -r '.data.hostname // "unknown"')
OUR_ADDRESS=$(echo "$OUR_INFO" | jq -r '.data.address // "unknown"')
echo "Hostname: $OUR_HOSTNAME | Address: $OUR_ADDRESS\n"
read -p "Enter target node hostname or address: " TARGET_NODE
[ -z "$TARGET_NODE" ] && echo "Error: Target required" && exit 1

TRUSTED=$(pilotctl --json trust | jq -r --arg target "$TARGET_NODE" '.data.trusted[] | select(.node_id == ($target | tonumber) or . == $target) | .node_id // empty')

if [ -z "$TRUSTED" ]; then
    read -p "No trust with $TARGET_NODE. Send handshake? (y/n): " SEND_HANDSHAKE
    if [ "$SEND_HANDSHAKE" = "y" ]; then
        pilotctl handshake "$TARGET_NODE" "event stream demo"
        echo "Handshake sent. Ask target to approve, then re-run."
        exit 0
    fi
    echo "Cannot proceed without trust."
    exit 1
fi

while true; do
    echo -e "\n${BLUE}=== Actions ===${NC}"
    echo "1. Publish event  2. Subscribe (bounded)  3. Subscribe (streaming)  4. Subscribe all  5. Exit"
    read -p "Select (1-5): " ACTION

    case $ACTION in
        1)
            read -p "\nTopic: " TOPIC
            read -p "Data: " EVENT_DATA
            RESULT=$(pilotctl --json publish "$TARGET_NODE" "$TOPIC" --data "$EVENT_DATA")
            [ $? -eq 0 ] && echo -e "${GREEN}✓ Published ($(echo "$RESULT" | jq -r '.data.bytes') bytes)${NC}" || echo "Error: $RESULT"
            ;;
        
        2)
            read -p "\nTopic (* for all): " TOPIC
            read -p "Count (default 10): " COUNT
            COUNT=${COUNT:-10}
            read -p "Timeout seconds (default 60): " TIMEOUT
            TIMEOUT=${TIMEOUT:-60}
            RESULT=$(pilotctl --json subscribe "$TARGET_NODE" "$TOPIC" --count "$COUNT" --timeout "${TIMEOUT}s")
            if [ $? -eq 0 ]; then
                EVENT_COUNT=$(echo "$RESULT" | jq -r '.data.events | length')
                echo -e "${GREEN}$EVENT_COUNT events:${NC}"
                echo "$RESULT" | jq -r '.data.events[] | "  [\(.topic)] \(.data)"'
            else
                echo "Error: $RESULT"
            fi
            ;;
        
        3)
            read -p "\nTopic (* for all): " TOPIC
            echo -e "${YELLOW}Streaming '$TOPIC'... Press Ctrl+C to stop.${NC}\n"
            pilotctl subscribe "$TARGET_NODE" "$TOPIC" | while IFS= read -r line; do
                EVENT_TOPIC=$(echo "$line" | jq -r '.topic // "unknown"')
                EVENT_DATA=$(echo "$line" | jq -r '.data // ""')
                echo -e "${BLUE}[$(date "+%H:%M:%S")]${NC} [$EVENT_TOPIC] $EVENT_DATA"
            done
            ;;
        
        4)
            read -p "\nCount (default 20): " COUNT
            COUNT=${COUNT:-20}
            read -p "Timeout seconds (default 60): " TIMEOUT
            TIMEOUT=${TIMEOUT:-60}
            RESULT=$(pilotctl --json subscribe "$TARGET_NODE" "*" --count "$COUNT" --timeout "${TIMEOUT}s")
            if [ $? -eq 0 ]; then
                EVENT_COUNT=$(echo "$RESULT" | jq -r '.data.events | length')
                echo -e "${GREEN}$EVENT_COUNT events from all topics:${NC}"
                echo "$RESULT" | jq -r '.data.events[] | "  [\(.topic)] \(.data)"'
            else
                echo "Error: $RESULT"
            fi
            ;;
        
        5)
            exit 0
            ;;
        
        *)
            echo "Invalid option."
            ;;
    esac
done
