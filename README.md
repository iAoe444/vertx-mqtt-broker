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
Requires Vert.x 3.1.x and Maven 3+

```
git clone https://github.com/GruppoFilippetti/vertx-mqtt-broker.git
cd vertx-mqtt-broker
mvn clean install
```

run as normal java ...
```
java -jar target/vertx-mqtt-broker-<version>-fat.jar -c config.json
```

Features
----
* Suport both QoS 0, 1 and 2 messages
* Persistence and session management (cleanSession=false)
* Multi-tenancy: isolation of topics and storage, (username@tenant)
* Pluggable authentication
* MQTT over WebSocket
* Retain flag
* Oauth2 authentication integrated with <a href="http://wso2.com/products/identity-server/">WSO2 Identity Server</a>
and <a href="http://apifest.com/">apifest.com</a>
* TLS support over TCP and Websocket
* Multiple endpoint configuration in the same broker instance
* Broker-to-Broker bidirectional bridge over websocket
