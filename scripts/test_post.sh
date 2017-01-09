#!/bin/bash

curl -XPOST \
    -d '{"test","snapshot"}' \
    -H "tenant: tenant.local" \
    "http://localhost:2883/pubsub/publish?channel=/tenant.local/channel/1"
