# v 2.2.7
- topic based authorization

# v 2.2.6
- compliance with mqtt paho integration suite for MQTT v 3.1.1 (Support for qos 1 and 2, will message, clean session, etc...)
- added a little http server to publish with a POST
    
        curl -XPOST \
        -d '{"test","snapshot"}' \
        -H "tenant: tenant.local" \
        "http://localhost:2883/pubsub/publish?channel=/tenant.local/channel/1"

- added authentication with clear user/pass on wso2 identity provider
- time eviction policy for retain messages
