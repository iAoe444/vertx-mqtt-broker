FROM openjdk:11-jre-slim

WORKDIR /opt

ADD target/vertx-mqtt-broker-2.5.2-fat.jar mqtt-broker.jar
ADD config.json config.json
ADD entrypoint.sh entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
CMD ["-c", "/opt/config.json"]
