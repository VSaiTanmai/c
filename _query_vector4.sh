#!/bin/sh
echo "=== SOURCES ==="
curl -s -X POST http://localhost:8686/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ sources { nodes { componentId metrics { sentEventsTotal { sentEventsTotal } receivedEventsTotal { receivedEventsTotal } } } } }"}'

echo ""
echo "=== SINKS ==="
curl -s -X POST http://localhost:8686/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ sinks { nodes { componentId metrics { sentEventsTotal { sentEventsTotal } receivedEventsTotal { receivedEventsTotal } } } } }"}'
