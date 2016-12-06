FROM openjdk:8-jre-alpine

WORKDIR /opt

ADD target/vertx-mqtt-broker-2.2.6-fat.jar mqtt-broker.jar
ADD config.json config.json

#ENTRYPOINT ["java", "-jar", "-XX:+ExitOnOutOfMemoryError", "-XX:+UseG1GC", "mqtt-broker.jar"]
CMD [
    "java",
    "-jar",
    "-XX:+ExitOnOutOfMemoryError",
    "-XX:+UseG1GC",
    "-Dcom.sun.management.jmxremote",
    "-Dcom.sun.management.jmxremote.port=9007",
    "-Dcom.sun.management.jmxremote.local.only=false",
    "-Dcom.sun.management.jmxremote.authenticate=false",
    "-Dcom.sun.management.jmxremote.ssl=false",
    "mqtt-broker.jar",
    "-c","/opt/config.json"]
