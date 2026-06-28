package com.modernisc.security.keycloak.credential;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;


public class KeycloakSmsAuthenticatorCredentialProviderFactory implements CredentialProviderFactory<KeycloakSmsAuthenticatorCredentialProvider> {
    @Override
    public String getId() {
        return "smsCode";
    }

    @Override
    public CredentialProvider create(KeycloakSession session) {
        return new KeycloakSmsAuthenticatorCredentialProvider(session);
    }
}
