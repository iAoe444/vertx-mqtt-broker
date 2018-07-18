package io.github.giovibal.mqtt.security.impl;

import io.github.giovibal.mqtt.security.AuthorizationClient;
import io.vertx.core.Future;
import io.vertx.core.eventbus.Message;
import io.vertx.core.eventbus.MessageConsumer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import it.filippetti.sp.auth.SPAuthHandler;

import java.util.Set;

/**
 * Uses JWT to validate user, theese are the 2 strategies:
 *
 * Tenant derive from clientID or username, if username contains "@"
 * parameters must be conform to 1 case, otherwise to 2 case:
 *
 * 1. Login with OAuth2 flow=password call:
 *    clientID: id@tenant
 *    username: user
 *    password: password
 *
 * 2. Login with JWT
 *    clientID: id@tenant
 *    username: jwt-access-token
 *    password: not used
 *
 */
public class JWTAuthenticatorVerticle extends AuthenticatorVerticle {

    private static Logger logger = LoggerFactory.getLogger(JWTAuthenticatorVerticle.class);

    private static String getEnv(String envName, String defaultVal) {
        String val = System.getenv().getOrDefault(envName, defaultVal);
        if(val == null) {
            String msg = String.format("Missing '%s' env var !", envName);
            logger.warn(msg);
        }
        return val;
    }

    @Override
    public void startAuthenticator(String address, AuthenticatorConfig c) throws Exception {
        String identityURL = getEnv("IDP_URL", c.getIdpUrl());
        String app_key = getEnv("CLIENT_ID", c.getAppKey());
        String app_secret = getEnv("CLIENT_SECRET", c.getAppSecret());

        SPAuthHandler spAuthHandler = SPAuthHandler.create(vertx);

        MessageConsumer<JsonObject> consumer = vertx.eventBus().consumer(address, (Message<JsonObject> msg) -> {
            JsonObject authReq = msg.body();
            String username = authReq.getString("username");
            String password = authReq.getString("password");
            String tenant = authReq.getString("tenant");

            // token validation
            try {
                HttpClientOptions opt = new HttpClientOptions();
                HttpClient httpClient = vertx.createHttpClient(opt);


                if(username!=null && username.contains("@")) {
                    login(httpClient, identityURL, app_key, app_secret, username, password).setHandler(loginEvt -> {
                        if(loginEvt.failed()) {
                            AuthorizationClient.ValidationInfo vi = new AuthorizationClient.ValidationInfo();
                            vi.auth_valid = false;
                            vi.authorized_user = "";
                            vi.error_msg = loginEvt.cause().getMessage();
                            msg.reply(vi.toJson());
                        } else {
                            String jwt = loginEvt.result();
                            setupProfile( spAuthHandler.validateJWT(jwt, tenant)).setHandler(event -> msg.reply(event.result()));
                        }
                    });
                }
                else {
                    // If username not contains "@", validate as JWT ...
                    String accessToken = username;
                    setupProfile( spAuthHandler.validateJWT(accessToken, tenant)).setHandler(event -> msg.reply(event.result()));
                }

            } catch (Throwable e) {
                logger.fatal(e.getMessage(), e);

                AuthorizationClient.ValidationInfo vi = new AuthorizationClient.ValidationInfo();
                vi.auth_valid = false;
                vi.authorized_user = "";
                vi.error_msg = e.getMessage();
                msg.reply(vi.toJson());
            }
        });

        logger.info("Startd MQTT Authorization, address: " + consumer.address());
    }

    private Future<JsonObject> setupProfile(Future<User> validateJWTResp) {
        Future<JsonObject> future = Future.future();

        validateJWTResp.setHandler(event -> {
            if(event.failed()) {
                Throwable e = event.cause();
                logger.fatal(e.getMessage(), e);

                AuthorizationClient.ValidationInfo vi = new AuthorizationClient.ValidationInfo();
                vi.auth_valid = false;
                vi.authorized_user = "";
                vi.error_msg = e.getMessage();
                future.complete(vi.toJson());
            } else {
                User user = event.result();
                String jsonResponse = user.principal().encode();
                logger.info(jsonResponse);

                JsonObject j = user.principal();
                logger.info("JWT: "+ j.encodePrettily());

                Long expiresIn = j.getLong("exp");
                String scope = j.getString("scope", null); // IGNORED
                boolean valid = true;
                String userId = j.getString("preferred_username");

                AuthorizationClient.ValidationInfo vi = new AuthorizationClient.ValidationInfo();
                vi.auth_valid = valid;
                vi.authorized_user = userId;
                vi.error_msg = "";

                JsonObject json = vi.toJson();
                json.put("scope", scope);
                json.put("expiry_time", expiresIn);

                logger.info("Profile: "+ json.encodePrettily());

                future.complete(json);
            }
        });
        return future;
    }


    private Future<String> login(HttpClient httpClient,
                                 String identityURL,
                                 String app_key,
                                 String app_secret,
                                 String username,
                                 String password) {
        Future<String> ret = Future.future();

        HttpClientRequest loginReq = httpClient.postAbs(identityURL, resp -> {
            resp.exceptionHandler(e -> {
                logger.fatal(e.getMessage(), e);
                ret.fail(e);
            });
            resp.bodyHandler(totalBuffer -> {
                String jsonResponse = totalBuffer.toString("UTF-8");
                logger.info(jsonResponse);
                JsonObject j = new JsonObject(jsonResponse);
                String access_token = j.getString("access_token");
                ret.complete(access_token);
            });
        });

        String data = "grant_type=password"
                + "&username=" + username
                + "&password=" + password
                + "&client_id=" + app_key
                + "&client_secret=" + app_secret
                + "";

        loginReq.putHeader("Content-Type", "application/x-www-form-urlencoded");
        loginReq.end(data, "UTF-8");

        return ret;
    }
}
