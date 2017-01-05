FROM openjdk:8-jre-alpine

WORKDIR /opt

ADD target/vertx-mqtt-broker-2.2.6-fat.jar mqtt-broker.jar
ADD config.json config.json
ADD entrypoint.sh entrypoint.sh

#ENTRYPOINT ["java", "-jar", "-XX:+ExitOnOutOfMemoryError", "-XX:+UseG1GC", "mqtt-broker.jar"]
#ENTRYPOINT ["java", "-jar", "-XX:+ExitOnOutOfMemoryError", "-XX:+UseG1GC", \
#    "-Dcom.sun.management.jmxremote", \
#    "-Dcom.sun.management.jmxremote.port=9007", \
#    "-Dcom.sun.management.jmxremote.local.only=false", \
#    "-Dcom.sun.management.jmxremote.authenticate=false", \
#    "-Dcom.sun.management.jmxremote.ssl=false", \
#    "-Djava.rmi.server.hostname=192.168.231.58", \
#    "mqtt-broker.jar"]
ENTRYPOINT ["./entrypoint.sh"]
CMD ["-c", "/opt/config.json"]
