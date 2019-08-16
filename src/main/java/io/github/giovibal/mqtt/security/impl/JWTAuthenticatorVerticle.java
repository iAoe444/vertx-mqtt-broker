package io.github.giovibal.mqtt.security.impl;

import io.github.giovibal.mqtt.security.AuthorizationClient;
import io.github.giovibal.mqtt.security.JWTUtils;
import io.vertx.core.Future;
import io.vertx.core.eventbus.Message;
import io.vertx.core.eventbus.MessageConsumer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.User;
import it.filippetti.sp.auth.SPAuthHandler;

/**
 * Uses JWT to validate user, theese are the 2 strategies:
 *
 * Tenant derive from clientID or username, if username contains "@"
 * parameters must be conform to case 1, otherwise to case 2:
 *
 * 1. Login with OAuth2 flow=password call:
 *    clientID (max 23 chars !!): id@tenant
 *    username: user
 *    password: password
 *
 * 2. Login with JWT
 *    clientID (max 23 chars !!): id@tenant
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
        logger.info(String.format("ENV: %s: %s", envName, val));
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
//                String jwt = password;
                String jwt = chooseJWT(username, password);
                Future<User> user = spAuthHandler.validateJWT(jwt, tenant);
                user.setHandler(jwtValidationEvent -> {
                    if(jwtValidationEvent.succeeded()) {
                        setupProfile(user).setHandler(event -> msg.reply(event.result()));
                    } else {
                        // ... JWT validation failed, try with plain user/pass to IDP
                        HttpClientOptions opt = new HttpClientOptions();
                        HttpClient httpClient = vertx.createHttpClient(opt);

                        login(httpClient, identityURL, app_key, app_secret, username, password).setHandler(loginEvt -> {
                            if(loginEvt.succeeded()) {
                                String jwtFromPlainAuth = loginEvt.result();
                                setupProfile( spAuthHandler.validateJWT(jwtFromPlainAuth, tenant)).setHandler(event -> msg.reply(event.result()));
                            } else {

                                String username2 = username +"@"+ tenant;
                                login(httpClient, identityURL, app_key, app_secret, username2, password).setHandler(loginEvt2 -> {
                                    if(loginEvt2.succeeded()) {
                                        String jwtFromPlainAuth2 = loginEvt2.result();
                                        setupProfile( spAuthHandler.validateJWT(jwtFromPlainAuth2, tenant)).setHandler(event -> msg.reply(event.result()));
                                    } else {
                                        AuthorizationClient.ValidationInfo vi = new AuthorizationClient.ValidationInfo();
                                        vi.auth_valid = false;
                                        vi.authorized_user = "";
                                        vi.error_msg = loginEvt2.cause().getMessage();
                                        msg.reply(vi.toJson());
                                    }
                                });

                            }
                        });
                    }
                });

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

                if(resp.statusCode() == 200) {
                    JsonObject j = new JsonObject(jsonResponse);
                    String access_token = j.getString("access_token");
                    ret.complete(access_token);
                } else {
                    logger.fatal(resp.statusMessage());
                    ret.fail(resp.statusMessage());
                }
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

    private String chooseJWT(String username, String password) {
        if(password == null || username == null) {
            throw new IllegalArgumentException("username and password cannot be null");
        }
        boolean usernameIsJWT = JWTUtils.isJWT(username);
        if(JWTUtils.isJWT(password)) {
            logger.info("JWT from password");
            return password;
        } else if(JWTUtils.isJWT(username)) {
            logger.info("JWT from username");
            return username;
        }

        if(password.length() > username.length()) {
            logger.info("JWT from password (password > username)");
            return password;
        } else if(username.length() > password.length()) {
            logger.info("JWT from username (username > password)");
            return username;
        } else {
            logger.info("JWT from password (default choice)");
            return password;
        }
    }
}
