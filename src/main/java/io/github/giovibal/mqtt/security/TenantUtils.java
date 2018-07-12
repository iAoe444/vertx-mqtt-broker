package io.github.giovibal.mqtt.security;

public class TenantUtils {
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

    public static void main(String[] args) {
        System.out.println(TenantUtils.extractTenant("user@tenant"));
        System.out.println(TenantUtils.extractTenant("tenant"));
        System.out.println(TenantUtils.extractTenant("user@test@tenant"));
    }
}
