#FROM java:8-alpine
FROM openjdk:8-jre-alpine

WORKDIR /opt

ADD target/vertx-mqtt-broker-2.2.5-fat.jar mqtt-broker.jar
ADD config.json config.json

ENTRYPOINT ["java", "-jar", "-XX:+ExitOnOutOfMemoryError", "-XX:+UseG1GC", "mqtt-broker.jar"]
CMD ["-c","/opt/config.json"]
