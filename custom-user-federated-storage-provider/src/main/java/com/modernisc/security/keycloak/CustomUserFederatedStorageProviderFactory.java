package com.modernisc.security.keycloak;


import jakarta.annotation.PostConstruct;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import org.keycloak.storage.federated.UserFederatedStorageProvider;
import org.keycloak.storage.federated.UserFederatedStorageProviderFactory;


public class CustomUserFederatedStorageProviderFactory implements
        UserFederatedStorageProviderFactory {


    private static final Logger logger = Logger.getLogger(CustomUserFederatedStorageProviderFactory.class);

    @Override
    public UserFederatedStorageProvider create(KeycloakSession keycloakSession) {

        return new CustomUserFederatedStorageProvider(keycloakSession);
    }


    @Override
    public String getId() {
        return "custom-user-Federated-Storage-provider";
    }

    @Override
    public void close() {
        logger.info("custom User custom-user-Federated-Storage-provider  Factory closed.");
    }


    @PostConstruct
    @Override
    public void init(Config.Scope config) {
        logger.info("Initializing custom-user-Federated-Storage-provider  Factory");
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

}