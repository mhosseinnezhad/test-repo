package com.modernisc.security.keycloak.users.cbank.util;

import org.eclipse.microprofile.config.ConfigProvider;

public class QuarkusUtil {

    /**
     * Reads a value from keycloak_home/conf/quarkus.properties by supplied key
     * @param key Supplied key
     * @return {@code String} Value of supplied key
     */
    public static String getProperty(String key) {
        return ConfigProvider.getConfig().getValue(key, String.class);
    }

}
