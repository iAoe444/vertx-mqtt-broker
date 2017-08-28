package io.github.giovibal.mqtt;

import io.github.giovibal.mqtt.prometheus.PromMetrics;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.ServerWebSocket;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

import java.util.Map;

/**
 * Created by giovanni on 07/05/2014.
 */
public class MQTTWebSocket extends MQTTSocket {
    
    private static Logger logger = LoggerFactory.getLogger(MQTTWebSocket.class);
    
    private ServerWebSocket netSocket;

    public MQTTWebSocket(Vertx vertx, ConfigParser config, ServerWebSocket netSocket, Map<String, MQTTSession> sessions) {
        super(vertx, config, sessions);
        this.netSocket = netSocket;
    }

    public void start() {
        netSocket.handler(this);
        netSocket.exceptionHandler(event -> {
            String clientInfo = getClientInfo();
            logger.info(clientInfo + ", web-socket closed ... " + netSocket.binaryHandlerID() + " error: " + event.getMessage());
            handleWillMessage();
            shutdown();
        });
        netSocket.closeHandler(aVoid -> {
            String clientInfo = getClientInfo();
            logger.info(clientInfo + ", web-socket closed ... "+ netSocket.binaryHandlerID() +" "+ netSocket.textHandlerID());
            shutdown();
        });
        vertx.setPeriodic(1000, event -> {
            PromMetrics.mqtt_sessions.setToCurrentTime();
            PromMetrics.mqtt_sessions.set(sessions.size());
        });
    }

    @Override
    protected void sendMessageToClient(Buffer bytes) {
        sendMessageToClient(bytes, netSocket, netSocket);
    }

    protected void closeConnection() {
        logger.debug("web-socket will be closed ... " + netSocket.binaryHandlerID() + " " + netSocket.textHandlerID());
        if(session!=null) {
            session.handleWillMessage();
        }
        netSocket.close();
    }
}
