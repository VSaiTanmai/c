#!/bin/sh
# Snapshot all component event totals as JSON
curl -s -X POST http://localhost:8686/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ sources { nodes { componentId metrics { sentEventsTotal { sentEventsTotal } } } } transforms { nodes { componentId metrics { sentEventsTotal { sentEventsTotal } receivedEventsTotal { receivedEventsTotal } } } } sinks { nodes { componentId metrics { sentEventsTotal { sentEventsTotal } receivedEventsTotal { receivedEventsTotal } } } } }"}'
