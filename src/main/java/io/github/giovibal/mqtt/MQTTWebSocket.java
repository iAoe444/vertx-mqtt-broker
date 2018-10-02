package io.github.giovibal.mqtt;

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
    
    private ServerWebSocket webSocket;

    public MQTTWebSocket(Vertx vertx, ConfigParser config, ServerWebSocket netSocket, Map<String, MQTTSession> sessions) {
        super(vertx, config, sessions);
        this.webSocket = netSocket;
    }

    public void start() {
        webSocket.handler(this);
        webSocket.exceptionHandler(event -> {
            String clientInfo = getClientInfo();
            logger.info(clientInfo + ", web-socket closed ... " + webSocket.binaryHandlerID() + " error: " + event.getMessage());
            handleWillMessage();
            shutdown();
        });
        webSocket.closeHandler(aVoid -> {
            String clientInfo = getClientInfo();
            logger.info(clientInfo + ", web-socket closed ... "+ webSocket.binaryHandlerID() +" "+ webSocket.textHandlerID());
            shutdown();
        });
    }

    @Override
    protected void sendMessageToClient(Buffer bytes) {
        sendMessageToClient(bytes, webSocket, webSocket);
    }

    protected void closeConnection() {
        logger.debug("web-socket will be closed ... " + webSocket.binaryHandlerID() + " " + webSocket.textHandlerID());
        if(session!=null) {
            session.handleWillMessage();
        }
        try {
            webSocket.close();
        } catch (IllegalStateException ise) {
            logger.warn(ise.getMessage());
        }
    }
}
