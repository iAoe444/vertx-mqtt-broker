package io.github.giovibal.mqtt.security.impl;

import com.sun.org.apache.xpath.internal.operations.Bool;
import io.github.giovibal.mqtt.security.AuthorizationClient;
import io.vertx.core.Future;
import io.vertx.core.eventbus.Message;
import io.vertx.core.eventbus.MessageConsumer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;

import java.net.URL;

public class JWTAuthenticatorVerticle extends AuthenticatorVerticle {
    private JWTAuth jwtAuth;

    @Override
    public void startAuthenticator(String address, AuthenticatorConfig c) throws Exception {


        String identityURL = c.getIdpUrl();
        String app_key = c.getAppKey();
        String app_secret = c.getAppSecret();
        String jwtPubKey = c.getJwtPubKey();

        JWTAuthOptions config = new JWTAuthOptions()
                .addPubSecKey(new PubSecKeyOptions()
                        .setAlgorithm("RS256")
                        .setPublicKey(jwtPubKey)
                )
                ;

        JWTAuth jwtAuth = JWTAuth.create(vertx, config);


        MessageConsumer<JsonObject> consumer = vertx.eventBus().consumer(address, (Message<JsonObject> msg) -> {
            JsonObject oauth2_token = msg.body();
            String username = oauth2_token.getString("username");
            String password = oauth2_token.getString("password");

            // token validation
            try {
                HttpClientOptions opt = new HttpClientOptions();
                HttpClient httpClient = vertx.createHttpClient(opt);
//                URL url = new URL(identityURL);

                String accessToken = username;

//                HttpClientRequest loginReq = httpClient.postAbs(identityURL, resp -> {
//                    resp.exceptionHandler(e -> {
//                        logger.fatal(e.getMessage(), e);
//
//                        AuthorizationClient.ValidationInfo vi = new AuthorizationClient.ValidationInfo();
//                        vi.auth_valid = false;
//                        vi.authorized_user = "";
//                        vi.error_msg = e.getMessage();
//                        msg.reply(vi.toJson());
//                    });
//                    resp.bodyHandler(totalBuffer -> {
//                        String jsonResponse = totalBuffer.toString("UTF-8");
//                        logger.info(jsonResponse);
//                        JsonObject j = new JsonObject(jsonResponse);
//                        String new_access_token = j.getString("access_token");
//                        Long expires_in = j.getLong("expires_in");
//                        String scope = j.getString("scope");
//                        String error = j.getString("error");
//
//                        AuthorizationClient.ValidationInfo vi = new AuthorizationClient.ValidationInfo();
//                        if(new_access_token != null && new_access_token.trim().length()>0) {
//                            vi.auth_valid = true;
//                            vi.authorized_user = username;
//                        } else {
//                            vi.auth_valid = false;
//                            vi.error_msg = error;
//                        }
//
//                        JsonObject json = vi.toJson();
//                        json.put("scope", scope);
//                        json.put("expiry_time", expires_in);
//
//                        msg.reply(json);
//                    });
//                });

                if(username!=null && username.contains("@")) {
//                    String data = "grant_type=password"
//                            + "&username=" + username
//                            + "&password=" + password
////                            + "&scope=sp"
//                            + "&client_id=" + app_key
//                            + "&client_secret=" + app_secret
//                            + "";
//
//                    loginReq.putHeader("Content-Type", "application/x-www-form-urlencoded");
//                    loginReq.end(data, "UTF-8");
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
