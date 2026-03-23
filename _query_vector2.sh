#!/bin/sh
# Query 1: Get component throughput from Vector GraphQL API
curl -s -X POST http://localhost:8686/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ components { nodes { componentId componentType on { ... on Source { metrics { sentEventsTotal receivedEventsTotal } } ... on Transform { metrics { sentEventsTotal receivedEventsTotal } } ... on Sink { metrics { sentEventsTotal receivedEventsTotal } } } } } }"}'
