vertx-mqtt-broker
=================

MQTT broker implementation based on Vert.x.

Credits:
<br/>
Moquette <a href="https://github.com/andsel/moquette">https://github.com/andsel/moquette</a>
for coder and decoder implementation of MQTT messages.
<br/>


Quick Start
-----------
1. Build from sources

```
git clone https://github.com/GruppoFilippetti/vertx-mqtt-broker.git
cd vertx-mqtt-broker
mvn clean install
```

2. Run 

```
java -jar target/vertx-mqtt-broker-<version>-fat.jar -c config.json
```

Features
----
* MQTT v3.1 and v3.1.1 support
* Suport both QoS 0, 1 and 2 messages
* Persistence and session management (cleanSession=false)
* Pluggable authentication (via vert.x verticle system)
    * OAuth 2.0 and OpenID Connect 1.0 authentication
    * JWT authentication
* Multi-tenancy
* MQTT over WebSocket
* Retain flag
* TLS support over TCP and Websocket
* Multiple tcp/websocket transports in the same broker engine
* Broker-to-Broker bidirectional and  bridge
