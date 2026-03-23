#!/bin/sh
# Get sources, transforms, sinks throughput
echo "=== SOURCES ==="
curl -s -X POST http://localhost:8686/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ sources { nodes { componentId metrics { sentEventsTotal { sentEventsTotal } receivedEventsTotal { receivedEventsTotal } sentEventBytesThroughput { sentEventBytesThroughput } } } } }"}'

echo ""
echo "=== TRANSFORMS ==="
curl -s -X POST http://localhost:8686/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ transforms { nodes { componentId metrics { sentEventsTotal { sentEventsTotal } receivedEventsTotal { receivedEventsTotal } } } } }"}'

echo ""
echo "=== SINKS ==="
curl -s -X POST http://localhost:8686/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ sinks { nodes { componentId metrics { sentEventsTotal { sentEventsTotal } receivedEventsTotal { receivedEventsTotal } sentEventBytesThroughput { sentEventBytesThroughput } } } } }"}'
