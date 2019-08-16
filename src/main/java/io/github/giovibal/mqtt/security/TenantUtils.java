package io.github.giovibal.mqtt.security;

import io.vertx.core.json.JsonObject;

public class TenantUtils {
    public static String extractTenantFromJWT(String jwt) {
        try {
            String payload = JWTUtils.decodeJWTPayoad(jwt);
            JsonObject jPayload = new JsonObject(payload);
            String username = jPayload.getString("preferred_username");
            return TenantUtils.extractTenant(username);
        } catch (Throwable e) {
            return "";
        }
    }

    public static String extractTenant(String username) {
        if(username == null || username.trim().length()==0)
            return "";
        String tenant = "";
        int idx = username.lastIndexOf('@');
        if(idx > 0) {
            tenant = username.substring(idx+1);
        }
        return tenant;
    }
    public static String removeTenant(String username) {
        if(username == null || username.trim().length()==0)
            return "";
        String tenant = username;
        int idx = username.lastIndexOf('@');
        if(idx > 0) {
            tenant = username.substring(0, idx);
        }
        return tenant;
    }

    public static void main(String[] args) {
        System.out.printf("user@tenant      => %s\n", TenantUtils.extractTenant("user@tenant"));
        System.out.printf("tenant           => %s\n", TenantUtils.extractTenant("tenant"));
        System.out.printf("user@test@tenant => %s\n", TenantUtils.extractTenant("user@test@tenant"));
        System.out.printf("null             => %s\n", TenantUtils.extractTenant(null));
        System.out.printf("                 => %s\n", TenantUtils.extractTenant(""));



        System.out.printf("user@tenant      => %s\n", TenantUtils.removeTenant("user@tenant"));
        System.out.printf("tenant           => %s\n", TenantUtils.removeTenant("tenant"));
        System.out.printf("user@test@tenant => %s\n", TenantUtils.removeTenant("user@test@tenant"));
        System.out.printf("null             => %s\n", TenantUtils.removeTenant(null));
        System.out.printf("                 => %s\n", TenantUtils.removeTenant(""));

        System.out.printf("from JWT         => %s\n", TenantUtils.extractTenantFromJWT("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJqOXFtS05hdXV5bzBYTExVa2VBR1RzTDdkWXhta2xlSEZPYXRUOGVnZTdJIn0.eyJqdGkiOiI2YmQzODhjNi1hOWExLTQ4NTYtOGVmZC01NjEzMTk3OTAxNjAiLCJleHAiOjE1NjcyNTQ1MjMsIm5iZiI6MCwiaWF0IjoxNTY1OTU4NTIzLCJpc3MiOiJodHRwczovL2lkcC5zbWFydHBsYXRmb3JtLmlvL2F1dGgvcmVhbG1zL3NwIiwiYXVkIjoiZGFzaGJvYXJkIiwic3ViIjoiNTc2NjNmZmMtOTY0OC00ZTA4LWIyMzEtZDYyNjdlZDQwN2VmIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZGFzaGJvYXJkIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiZmU1NjdiZjAtMGQzOC00YjA5LWJiOTAtN2FkZjc4ZWZkODJhIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2Rhc2hib2FyZC5zbWFydHBsYXRmb3JtLmlvIiwiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiaHR0cHM6Ly9kYXNoYm9hcmQuZWltd2FyZS5pdCIsImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsibWVjY2FybmkubGV2b25pLml0IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJwb3J0aW5lcmlhQG1lY2Nhcm5pLmxldm9uaS5pdCJ9.l8cqqmXYknXnpYqUtD0-EqGINqqjboio1KNt0SiKEetyRatYpT8SAwKdZvb7zZbYWV0vHLT3QnNDNcpdyNbDgI1u4aY7dZTjil0tnoqTFRGFM4XLkmAXAADNkrBTI0iw-JFBlW37WIhmKE6LR6IwCRlFbd3-IylH_kgN35pSIdpaZV0dFLR4M2dnQpxHvVAihyKoiYI6eNN2YkcCxqIx5JK3bnVxuWHX_bOBOOKQ_boiBG0BlZx1_mOvpqj3NL-dgYv87bidqeXlaou42RsBJhG1KCLrDOtKhmMuKhbk9Z9fVoDfHJHdXFrZzaO-WauuavgIOvwQ3Th50Wt0utXT_A"));
    }
}
