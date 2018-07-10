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

import java.util.Set;

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
        String jwtPubKey = getEnv("JWT_PUB_KEY", null);
        String jwtPubKeys = getEnv("JWT_PUB_KEYS", null);

        JWTAuthOptions config = new JWTAuthOptions();

        if(jwtPubKey!=null) {
            config.addPubSecKey(new PubSecKeyOptions()
                    .setAlgorithm("RS256")
                    .setPublicKey(jwtPubKey)
            );
        }
        if(jwtPubKeys!=null) {
            JsonObject jwtPubKeysJson = new JsonObject(jwtPubKeys);
            Set<String> kids = jwtPubKeysJson.fieldNames();
            for(String kid : kids) {
                String _jwtPubKey = jwtPubKeysJson.getString(kid);
                config.addPubSecKey(new PubSecKeyOptions()
                        .setAlgorithm("RS256")
                        .setPublicKey(_jwtPubKey)
                );
            }
        }

        JWTAuth jwtAuth = JWTAuth.create(vertx, config);

        MessageConsumer<JsonObject> consumer = vertx.eventBus().consumer(address, (Message<JsonObject> msg) -> {
            JsonObject oauth2_token = msg.body();
            String username = oauth2_token.getString("username");
            String password = oauth2_token.getString("password");

            // token validation
            try {
                HttpClientOptions opt = new HttpClientOptions();
                HttpClient httpClient = vertx.createHttpClient(opt);

                String accessToken = username;

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
                            setupProfile( validateJWT(jwtAuth, jwt) ).setHandler(event -> msg.reply(event.result()));
                        }
                    });
                }
                else {
                    // If username not contains "@", validate as JWT ...
                    setupProfile( validateJWT(jwtAuth, accessToken) ).setHandler(event -> msg.reply(event.result()));
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

    private Future<User> validateJWT(JWTAuth jwtAuth, String jwt) {
        Future<User> future = Future.future();

        jwtAuth.authenticate(new JsonObject().put("jwt", jwt), res -> {
            if (res.succeeded()) {
                User theUser = res.result();
                System.out.println(theUser.principal().encodePrettily());
                future.complete(theUser);
            } else {
                // Failed!
                future.fail(res.cause());
            }
        });

        return future;
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
                String tenant = j.getString("tenant", null);

                AuthorizationClient.ValidationInfo vi = new AuthorizationClient.ValidationInfo();
                vi.auth_valid = valid;
                vi.authorized_user = userId;
                vi.tenant = tenant;
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
