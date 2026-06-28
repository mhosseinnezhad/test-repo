package com.modernisc.security.keycloak;

import org.junit.Test;
import org.wildfly.security.util.PasswordBasedEncryptionUtil;

import java.security.GeneralSecurityException;

public class PasswordMaskTest {

    @Test
    public void generateMaskedPassword() throws GeneralSecurityException {
        String secret = "VPSwcLpwGqZjcobFSENABLjoLkBdqA6F";
        String salt = "12345678";
        int iteration = 50;

        System.out.println(computeMasked(secret, salt, iteration));
    }

    static String computeMasked(String secret, String salt, int iteration) throws GeneralSecurityException {
        PasswordBasedEncryptionUtil encryptUtil = new PasswordBasedEncryptionUtil.Builder()
                .picketBoxCompatibility()
                .salt(salt)
                .iteration(iteration)
                .encryptMode()
                .build();
        return "MASK-" + encryptUtil.encryptAndEncode(secret.toCharArray()) + ";" + salt + ";" + String.valueOf(iteration);
    }

}
