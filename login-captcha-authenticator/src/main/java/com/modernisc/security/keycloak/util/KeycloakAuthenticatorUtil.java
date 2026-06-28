package com.modernisc.security.keycloak.util;

import org.keycloak.models.AuthenticatorConfigModel;

/**
 * Deprecated. Use QuarkusUtil instead.
 */
@Deprecated
public class KeycloakAuthenticatorUtil {

    public static String getConfigString(AuthenticatorConfigModel config, String configName) {
        return getConfigString(config, configName, null);
    }

    public static String getConfigString(AuthenticatorConfigModel config, String configName, String defaultValue) {

        String value = defaultValue;
        if (config.getConfig() != null) {
            // Get value
            value = config.getConfig().get(configName);
        } else {
            value = "0";
        }
        return value;
    }

}
