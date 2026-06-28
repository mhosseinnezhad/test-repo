package com.modernisc.security.keycloak;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jboss.logging.Logger;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static com.modernisc.security.keycloak.util.ExceptionUtil.getChainCauseMessage;

public class RuntimeEncryptor {

    private static final Logger logger = Logger.getLogger(RuntimeEncryptor.class);

    private static String algorithm = "PBEWITHSHA256AND128BITAES-CBC-BC";
    private static StandardPBEStringEncryptor encryptor;


    static {
        encryptor = new StandardPBEStringEncryptor();
        encryptor.setAlgorithm(algorithm);
        try {
            encryptor.setPassword("" + SecureRandom.getInstance("SHA1PRNG"));
        } catch (NoSuchAlgorithmException exp) {
            logger.error("captcha encryption error: " + getChainCauseMessage(exp));
        }
    }

    public static String encrypt(String expr) {
        return encryptor.encrypt(expr);
    }

    public static String decrypt(String encExpr) {
        return encryptor.decrypt(encExpr);
    }
}
