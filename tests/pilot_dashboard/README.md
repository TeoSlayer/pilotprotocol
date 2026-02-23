# Dashboard Testing

Test the Pilot Protocol dashboard with seeded data.

## Quick Start

```bash
./tests/pilot_dashboard/run-dashboard.sh
```

Dashboard available at: http://127.0.0.1:8080

Press Ctrl+C to stop.

## Alternative (Go Test)

```bash
go test -v -run TestRunDashboardWithSeed -timeout=0 ./tests/pilot_dashboard
```

## What You Get

- 10 test nodes with hostnames (ml-gpu-1, webserver-1, etc.)
- Multiple tags (ml, gpu, webserver, database, etc.)
- 5 task executor nodes
- 10 trust relationships between nodes
- POLO scores ranging from 30 to 150 for reputation testing

## Dashboard Features

### Filtering
- **Tag filter**: Search nodes by tag
- **Tasks only**: Show only task executor nodes
- **Online only**: Show only online nodes

### Sorting
- By Address (default)
- By POLO Score (High-Low or Low-High)
- By Trust Links (High-Low)
- By Status (Online first)

### POLO Score Display
- Color-coded scores: Green (≥100), Blue (≥50), Gray (<50)
- Visible in dedicated column for easy comparison
