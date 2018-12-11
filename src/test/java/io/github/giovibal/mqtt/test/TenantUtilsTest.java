package io.github.giovibal.mqtt.test;

import io.github.giovibal.mqtt.security.TenantUtils;
import org.junit.Assert;
import org.junit.Test;

public class TenantUtilsTest {
    @Test
    public void extractTenantTest() {
        Assert.assertEquals("tenant", TenantUtils.extractTenant("user@tenant"));
        Assert.assertEquals("",       TenantUtils.extractTenant("tenant"));
        Assert.assertEquals("tenant", TenantUtils.extractTenant("user@test@tenant"));
        Assert.assertEquals("",       TenantUtils.extractTenant(null));
        Assert.assertEquals("",       TenantUtils.extractTenant(""));
    }

    @Test
    public void removeTenantTest() {
        Assert.assertEquals("user",      TenantUtils.removeTenant("user@tenant"));
        Assert.assertEquals("user",    TenantUtils.removeTenant("user"));
        Assert.assertEquals("user@test", TenantUtils.removeTenant("user@test@tenant"));
        Assert.assertEquals("",          TenantUtils.removeTenant(null));
        Assert.assertEquals("",          TenantUtils.removeTenant(""));
    }
}
