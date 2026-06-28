package com.modernisc.security.keycloak.users.util;

public class ExceptionUtil {

    public static String getChainCauseMessage(Throwable exception) {
        Throwable cause = exception;

        String chainCauseMessage = null;

        while (cause != null) {
            if (chainCauseMessage == null){
                chainCauseMessage = cause.getMessage();
            }
            else{
                chainCauseMessage += " => " + cause.getMessage();
            }

            cause = cause.getCause();
        }

        return chainCauseMessage;
    }
}
