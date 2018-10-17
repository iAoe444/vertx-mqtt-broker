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
    }
}
