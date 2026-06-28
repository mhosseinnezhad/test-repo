package com.modernisc.security.keycloak;

/**
 * SMS provder interface
 */
public interface SMSService {
    boolean send(String phoneNumber, String message, String login, String pw);
}
