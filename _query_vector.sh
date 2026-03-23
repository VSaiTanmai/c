#!/bin/sh
curl -s -X POST http://localhost:8686/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ componentSentEventsTotals { componentId componentType metric { sentEventsTotal } } }"}'
