package io.github.giovibal.mqtt.security.impl;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by Giovanni Baleani on 23/02/2015.
 */
public class AuthenticatorConfig {

    private List<String> authorizedClients;
    private String idpUrl;
    private String idpUsername;
    private String idpPassword;
    private String appKey;
    private String appSecret;

    public AuthenticatorConfig(JsonObject conf) {
        parse(conf);
    }
    public void parse(JsonObject conf) {
        JsonObject security = conf.getJsonObject("security", new JsonObject());
        JsonArray authorizedClientsArr = security.getJsonArray("authorized_clients", new JsonArray());
        if(authorizedClientsArr != null) {
            authorizedClients = new ArrayList<>();
            for(int i=0; i<authorizedClientsArr.size(); i++) {
                String item = authorizedClientsArr.getString(i);
                authorizedClients.add(item);
            }
        }
        idpUrl = security.getString("idp_url", null);
        idpUsername = security.getString("idp_username", null);
        idpPassword = security.getString("idp_password", null);
        appKey = security.getString("app_key", null);
        appSecret = security.getString("app_secret", null);
    }

    public List<String> getAuthorizedClients() {
        return authorizedClients;
    }

    public String getIdpUrl() {
        return idpUrl;
    }

    public String getIdpUsername() {
        return idpUsername;
    }

    public String getIdpPassword() {
        return idpPassword;
    }

    public String getAppKey() {
        return appKey;
    }

    public String getAppSecret() {
        return appSecret;
    }

    public boolean isAuthorizedClient(String clientID) {
        if(authorizedClients!=null) {
            for(String ac : authorizedClients) {
                if(clientID.matches(ac)) {
                    return true;
                }
            }
        }
        return false;
    }
}
