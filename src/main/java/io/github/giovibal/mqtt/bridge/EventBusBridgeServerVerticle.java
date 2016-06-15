package io.github.giovibal.mqtt.bridge;

import io.github.giovibal.mqtt.Container;
import io.github.giovibal.mqtt.MQTTSession;
import io.github.giovibal.mqtt.security.CertInfo;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.ClientAuth;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.core.net.NetServer;
import io.vertx.core.net.NetServerOptions;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.core.net.PemTrustOptions;
import io.vertx.core.parsetools.RecordParser;

/**
 * Created by Giovanni Baleani on 15/07/2015.
 */
public class EventBusBridgeServerVerticle extends AbstractVerticle {

    private static Logger logger = LoggerFactory.getLogger(EventBusBridgeServerVerticle.class);

    private NetServer netServer;
    private String address;
    private int localBridgePort;
    private int idleTimeout;
    private String ssl_cert_key;
    private String ssl_cert;
    private String ssl_trust;

    @Override
    public void start() throws Exception {

        JsonObject conf = config();

        localBridgePort = conf.getInteger("local_bridge_port", 7007);
        address = MQTTSession.ADDRESS;
        idleTimeout = conf.getInteger("socket_idle_timeout", 120);
        ssl_cert_key = conf.getString("ssl_cert_key");
        ssl_cert = conf.getString("ssl_cert");
        ssl_trust = conf.getString("ssl_trust");


        // [TCP -> BUS] listen TCP publish to BUS
        NetServerOptions opt = new NetServerOptions()
                .setTcpKeepAlive(true)
                .setIdleTimeout(idleTimeout)
                .setPort(localBridgePort)
        ;

        if(ssl_cert_key != null && ssl_cert != null && ssl_trust != null) {
            opt.setSsl(true).setClientAuth(ClientAuth.REQUIRED)
                .setPemKeyCertOptions(new PemKeyCertOptions()
                    .setKeyPath(ssl_cert_key)
                    .setCertPath(ssl_cert)
                )
                .setPemTrustOptions(new PemTrustOptions()
                    .addCertPath(ssl_trust)
                )
            ;
        }

        netServer = vertx.createNetServer(opt);
        netServer.connectHandler(netSocket -> {
            final EventBusNetBridge ebnb = new EventBusNetBridge(netSocket, vertx.eventBus(), address);
            netSocket.closeHandler(aVoid -> {
                logger.info("Bridge Server - closed connection from client ip: " + netSocket.remoteAddress());
                ebnb.stop();
            });
            netSocket.exceptionHandler(throwable -> {
                logger.error("Bridge Server - Exception: " + throwable.getMessage(), throwable);
                ebnb.stop();
            });

            logger.info("Bridge Server - new connection from client ip: " + netSocket.remoteAddress());



            final RecordParser parser = RecordParser.newDelimited("\n", h -> {
                String cmd = h.toString();
                if("START SESSION".equalsIgnoreCase(cmd)) {
                    netSocket.pause();
                    ebnb.start();
                    logger.info("Bridge Server - start session with tenant: " + ebnb.getTenant() +", ip: " + netSocket.remoteAddress() +", bridgeUUID: " + ebnb.getBridgeUUID());
                    netSocket.resume();
                } else {
                    String tenant = cmd;
                    String tenantFromCert = new CertInfo(netSocket).getTenant();
//                    if(!tenant.equals(tenantFromCert))
//                        throw new IllegalAccessError("Bridge Authentication Failed for tenant: "+ tenant +"/"+ tenantFromCert);
                    if(tenantFromCert != null)
                        tenant = tenantFromCert;

                    ebnb.setTenant(tenant);
                }
            });
            netSocket.handler(parser::handle);

        }).listen();
    }

    @Override
    public void stop() throws Exception {
        netServer.close();
    }

}
