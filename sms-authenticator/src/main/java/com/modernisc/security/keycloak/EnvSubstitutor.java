package com.modernisc.security.keycloak;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.text.StrLookup;
import org.apache.commons.lang.text.StrSubstitutor;
import org.jboss.logging.Logger;

public class EnvSubstitutor {

    public static final StrSubstitutor envSubstitutor =
            new StrSubstitutor(new EnvLookUp());

    private static final Logger logger =
            Logger.getLogger(EnvSubstitutor.class);

    private static class EnvLookUp extends StrLookup {

        @Override
        public String lookup(String key) {

            String value = System.getProperty(key);

            if (StringUtils.isBlank(value)) {
                value = System.getenv(key);
            }

            if (StringUtils.isBlank(value)) {
                throw new IllegalArgumentException(
                        "Key '" + key + "' was not found in system properties or environment variables.");
            }

            return value;
        }
    }
}