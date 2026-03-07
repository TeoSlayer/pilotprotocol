#!/bin/bash
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=== Task Submit Service Demo ===${NC}\n"

if ! pilotctl --json daemon status --check 2>/dev/null; then
    pilotctl daemon start
fi

OUR_INFO=$(pilotctl --json info)
OUR_HOSTNAME=$(echo "$OUR_INFO" | jq -r '.data.hostname // "unknown"')
OUR_ADDRESS=$(echo "$OUR_INFO" | jq -r '.data.address // "unknown"')
echo "Hostname: $OUR_HOSTNAME | Address: $OUR_ADDRESS\n"

while true; do
    echo -e "\n${BLUE}=== Actions ===${NC}"
    echo "1. Submit task  2. Check received  3. View queue  4. Process task  5. Check submitted  6. View results  7. Worker mode  8. Exit"
    read -p "Select (1-8): " ACTION

    case $ACTION in
        1)
            read -p "\nTarget node: " TARGET_NODE
            [ -z "$TARGET_NODE" ] && echo "Error: Target required" && continue
            TRUSTED=$(pilotctl --json trust | jq -r --arg target "$TARGET_NODE" '.data.trusted[] | select(.node_id == ($target | tonumber) or . == $target) | .node_id // empty')
            if [ -z "$TRUSTED" ]; then
                read -p "No trust. Send handshake? (y/n): " SEND_HANDSHAKE
                [ "$SEND_HANDSHAKE" = "y" ] && pilotctl handshake "$TARGET_NODE" "task submit demo" && echo "Handshake sent."
                continue
            fi
            read -p "Task description: " TASK_DESC
            RESULT=$(pilotctl --json task submit "$TARGET_NODE" --task "$TASK_DESC")
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✓ Task submitted: $(echo "$RESULT" | jq -r '.data.task_id')${NC}"
            else
                echo "Error: $RESULT"
            fi
            ;;
        
        2)
            TASKS=$(pilotctl --json task list --type received)
            TASK_COUNT=$(echo "$TASKS" | jq -r '.data.tasks | length')
            [ "$TASK_COUNT" -eq 0 ] && echo "\nNo tasks received." && continue
            echo -e "\n${GREEN}$TASK_COUNT task(s):${NC}"
            echo "$TASKS" | jq -r '.data.tasks[] | "  [\(.status)] \(.task_id): \(.description)"'
            NEW_COUNT=$(echo "$TASKS" | jq -r '[.data.tasks[] | select(.status == "NEW")] | length')
            [ "$NEW_COUNT" -gt 0 ] && echo -e "${RED}⚠ $NEW_COUNT NEW task(s) - accept/decline within 1 minute!${NC}"
            ;;
        
        3)
            QUEUE=$(pilotctl --json task queue)
            QUEUE_SIZE=$(echo "$QUEUE" | jq -r '.data.queue | length')
            [ "$QUEUE_SIZE" -eq 0 ] && echo "\nQueue empty." && continue
            echo -e "\n${GREEN}Queue ($QUEUE_SIZE tasks):${NC}"
            echo "$QUEUE" | jq -r '.data.queue[] | "  \(.position). \(.task_id): \(.description)"'
            ;;
        
        4)
            read -p "\nTask ID: " TASK_ID
            [ -z "$TASK_ID" ] && echo "Task ID required" && continue
            TASK_INFO=$(pilotctl --json task list --type received | jq -r --arg id "$TASK_ID" '.data.tasks[] | select(.task_id == $id)')
            [ -z "$TASK_INFO" ] && echo "Task not found" && continue
            STATUS=$(echo "$TASK_INFO" | jq -r '.status')
            DESCRIPTION=$(echo "$TASK_INFO" | jq -r '.description')
            echo "Status: $STATUS | Description: $DESCRIPTION"
            
            case $STATUS in
                NEW)
                    read -p "Accept? (y/n): " ACCEPT
                    if [ "$ACCEPT" = "y" ]; then
                        pilotctl task accept --id "$TASK_ID" && echo -e "${GREEN}✓ Accepted${NC}"
                    else
                        read -p "Decline reason: " JUST
                        pilotctl task decline --id "$TASK_ID" --justification "$JUST" && echo -e "${GREEN}✓ Declined${NC}"
                    fi
                    ;;
                ACCEPTED)
                    read -p "Execute? (y/n): " EXEC
                    [ "$EXEC" != "y" ] && continue
                    pilotctl task execute
                    read -p "\n[Do the work now] Press Enter when done..."
                    read -p "Results (1=text, 2=file): " RTYPE
                    if [ "$RTYPE" = "1" ]; then
                        read -p "Results text: " RTXT
                        pilotctl task send-results --id "$TASK_ID" --results "$RTXT" && echo -e "${GREEN}✓ Sent${NC}"
                    elif [ "$RTYPE" = "2" ]; then
                        read -p "Results file: " RFILE
                        [ -f "$RFILE" ] && pilotctl task send-results --id "$TASK_ID" --file "$RFILE" && echo -e "${GREEN}✓ Sent${NC}"
                    fi
                    ;;
                EXECUTING)
                    read -p "Send results now? (y/n): " SEND
                    [ "$SEND" != "y" ] && continue
                    read -p "Results (1=text, 2=file): " RTYPE
                    if [ "$RTYPE" = "1" ]; then
                        read -p "Results text: " RTXT
                        pilotctl task send-results --id "$TASK_ID" --results "$RTXT" && echo -e "${GREEN}✓ Sent${NC}"
                    elif [ "$RTYPE" = "2" ]; then
                        read -p "Results file: " RFILE
                        [ -f "$RFILE" ] && pilotctl task send-results --id "$TASK_ID" --file "$RFILE" && echo -e "${GREEN}✓ Sent${NC}"
                    fi
                    ;;
                *)
                    echo "Task in $STATUS (no action)."
                    ;;
            esac
            ;;
        
        5)
            SUBMITTED=$(pilotctl --json task list --type submitted)
            TASK_COUNT=$(echo "$SUBMITTED" | jq -r '.data.tasks | length')
            [ "$TASK_COUNT" -eq 0 ] && echo "\nNo tasks submitted." && continue
            echo -e "\n${GREEN}$TASK_COUNT submitted:${NC}"
            echo "$SUBMITTED" | jq -r '.data.tasks[] | "  [\(.status)] \(.task_id): \(.description)"'
            ;;
        
        6)
            RESULTS_DIR="$HOME/.pilot/tasks/results"
            [ ! -d "$RESULTS_DIR" ] && echo "\nNo results directory." && continue
            RESULT_FILES=$(ls -1 "$RESULTS_DIR" 2>/dev/null | grep -E '.*_result\.(txt|json)$' || true)
            [ -z "$RESULT_FILES" ] && echo "\nNo results found." && continue
            echo -e "\n${GREEN}Results:${NC}"
            echo "$RESULT_FILES" | while read -r file; do echo "  $file"; done
            read -p "View file (or Enter to skip): " RFILE
            [ -n "$RFILE" ] && [ -f "$RESULTS_DIR/$RFILE" ] && cat "$RESULTS_DIR/$RFILE"
            ;;
        
        7)
            echo -e "\n${YELLOW}Worker mode - checking every 10s. Ctrl+C to exit.${NC}"
            while true; do
                echo -e "\n${BLUE}[$(date "+%H:%M:%S")] Checking...${NC}"
                TASKS=$(pilotctl --json task list --type received)
                NEW_TASKS=$(echo "$TASKS" | jq -r '[.data.tasks[] | select(.status == "NEW")] | .[].task_id')
                if [ -n "$NEW_TASKS" ]; then
                    echo "$NEW_TASKS" | while read -r TID; do
                        DESC=$(echo "$TASKS" | jq -r --arg id "$TID" '[.data.tasks[] | select(.task_id == $id)] | .[0].description')
                        echo "New task: $TID - $DESC"
                        read -p "Accept? (y/n): " ACC
                        if [ "$ACC" = "y" ]; then
                            pilotctl task accept --id "$TID" && echo -e "${GREEN}✓ Accepted${NC}"
                        else
                            read -p "Decline reason: " JUST
                            pilotctl task decline --id "$TID" --justification "$JUST" && echo -e "${GREEN}✓ Declined${NC}"
                        fi
                    done
                else
                    echo "No new tasks."
                fi
                sleep 10
            done
            ;;
        
        8)
            exit 0
            ;;
        
        *)
            echo "Invalid option."
            ;;
    esac
done
