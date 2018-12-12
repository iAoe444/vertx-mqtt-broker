# v 2.5.1
- Slim down docker image

# v 2.5.0
- Updated openjdk to v11

# v 2.4.1
- Authentication retrocompatibility, now supports this additional strategies:
    if tenant is null or empty: extract username form jwt (attrib: "preferred_username"), and extract tenant from username
    if username is "user@tenant", try plain with "user" and "user@tenant"  

# v 2.4.0
- Updated sp-vertx-auth to v1.0.4 as dependency
- Only JWT auth 
    clientid: <free id>
    username: <user>@<tenant>
    password: <jwt access token>
     
# v 2.3.1
- added sp-vertx-auth:1.0.2 as dependency

# v 2.3.0
- JWT authorization support, 
now clients **must** include tenant in "clienID" during mqtt-connect, 
using this pattern: 
        
        [client-id]@[tenant]

# v 2.2.14
- JWT auth support 

# v 2.2.13
- bug fixing

# v 2.2.12
- updated vert.x dependencies to v3.5.0
- better handling of auth with null username
- debug of auth with user/pass using wso2 as identity provider

# v 2.2.11
- added better support of sessions with prometheus metrics
- changed default auth verticle instances from 1 to 5

# v 2.2.10
- added support for prometheus metrics

# v 2.2.9
- bugfixing: retain with void or null tenant

# v 2.2.8
- topic based authorization

# v 2.2.7
- Resolved Out Of Memory: tested with 7000 msg/sec with 10 subscribers for about 2 month
- Fix null pointer exception during HAClient tests

# v 2.2.6
- compliance with mqtt paho integration suite for MQTT v 3.1.1 (Support for qos 1 and 2, will message, clean session, etc...)
- added a little http server to publish with a POST
    
        curl -XPOST \
        -d '{"test","snapshot"}' \
        -H "tenant: tenant.local" \
        "http://localhost:2883/pubsub/publish?channel=/tenant.local/channel/1"

- added authentication with clear user/pass on wso2 identity provider
- time eviction policy for retain messages
