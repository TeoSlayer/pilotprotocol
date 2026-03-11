#!/bin/bash
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}=== Data Exchange Service Demo ===${NC}\n"

if ! pilotctl --json daemon status --check 2>/dev/null; then
    pilotctl daemon start
fi

echo -e "${YELLOW}Getting node identity...${NC}"
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
        pilotctl handshake "$TARGET_NODE" "data exchange demo"
        echo "Handshake sent. Ask target to approve, then re-run."
        exit 0
    fi
    echo "Cannot proceed without trust."
    exit 1
fi

while true; do
    echo -e "\n${BLUE}=== Actions ===${NC}"
    echo "1. Send text  2. Send JSON  3. Send file  4. Check files  5. Check inbox  6. Exit"
    read -p "Select (1-6): " ACTION

    case $ACTION in
        1)
            read -p "\nMessage text: " MESSAGE_TEXT
            RESULT=$(pilotctl --json send-message "$TARGET_NODE" --data "$MESSAGE_TEXT" --type text)
            [ $? -eq 0 ] && echo -e "${GREEN}✓ Sent ($(echo "$RESULT" | jq -r '.data.bytes') bytes)${NC}" || echo "Error: $RESULT"
            ;;
        
        2)
            read -p "\nJSON message: " JSON_MSG
            RESULT=$(pilotctl --json send-message "$TARGET_NODE" --data "$JSON_MSG" --type json)
            [ $? -eq 0 ] && echo -e "${GREEN}✓ Sent ($(echo "$RESULT" | jq -r '.data.bytes') bytes)${NC}" || echo "Error: $RESULT"
            ;;
        
        3)
            read -p "\nFile path: " FILE_PATH
            [ ! -f "$FILE_PATH" ] && echo "Error: File not found" && continue
            RESULT=$(pilotctl --json send-file "$TARGET_NODE" "$FILE_PATH")
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✓ Sent: $(echo "$RESULT" | jq -r '.data.filename') ($(echo "$RESULT" | jq -r '.data.bytes') bytes)${NC}"
            else
                echo "Error: $RESULT"
            fi
            ;;
        
        4)
            RECEIVED=$(pilotctl --json received)
            TOTAL=$(echo "$RECEIVED" | jq -r '.data.total // 0')
            if [ "$TOTAL" -eq 0 ]; then
                echo "\nNo files received."
            else
                echo "\n$TOTAL file(s):"
                echo "$RECEIVED" | jq -r '.data.files[] | "  \(.name) (\(.bytes) bytes)"'
                read -p "Clear? (y/n): " CLEAR
                [ "$CLEAR" = "y" ] && pilotctl received --clear && echo -e "${GREEN}✓ Cleared${NC}"
            fi
            ;;
        
        5)
            INBOX=$(pilotctl --json inbox)
            TOTAL=$(echo "$INBOX" | jq -r '.data.total // 0')
            if [ "$TOTAL" -eq 0 ]; then
                echo "\nNo messages in inbox."
            else
                echo "\n$TOTAL message(s):"
                echo "$INBOX" | jq -r '.data.messages[] | "  [\(.type)] from \(.from): \(.data)"'
                read -p "Clear? (y/n): " CLEAR
                [ "$CLEAR" = "y" ] && pilotctl inbox --clear && echo -e "${GREEN}✓ Cleared${NC}"
            fi
            ;;
        
        6)
            exit 0
            ;;
        
        *)
            echo "Invalid option."
            ;;
    esac
done
