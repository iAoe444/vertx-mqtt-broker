package io.github.giovibal.mqtt;

import io.github.giovibal.mqtt.prometheus.PromMetrics;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.core.net.NetSocket;

import java.util.Map;

/**
 * Created by giovanni on 07/05/2014.
 */
public class MQTTNetSocket extends MQTTSocket {

    private static Logger logger = LoggerFactory.getLogger(MQTTNetSocket.class);

    private NetSocket netSocket;

    public MQTTNetSocket(Vertx vertx, ConfigParser config, NetSocket netSocket, Map<String, MQTTSession> sessions) {
        super(vertx, config,sessions);
        this.netSocket = netSocket;
    }

    public void start() {
        netSocket.handler(this);
        netSocket.exceptionHandler(event -> {
            String clientInfo = getClientInfo();
            logger.error(clientInfo + ", net-socket closed ... " + netSocket.writeHandlerID() + " error: " + event.getMessage(), event.getCause());
            handleWillMessage();
            shutdown();
        });
        netSocket.closeHandler(aVoid -> {
            String clientInfo = getClientInfo();
            logger.info(clientInfo + ", net-socket closed ... " + netSocket.writeHandlerID());
            handleWillMessage();
            shutdown();
        });
        vertx.setPeriodic(1000, event -> {
            PromMetrics.mqtt_sessions.set(sessions.size());
        });
    }


    @Override
    protected void sendMessageToClient(Buffer bytes) {
        sendMessageToClient(bytes, netSocket, netSocket);
    }

    protected void closeConnection() {
        logger.debug("net-socket will be closed ... " + netSocket.writeHandlerID());
        netSocket.close();
    }

}
