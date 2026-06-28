package com.modernisc.security.keycloak.iam.kc;

import com.modernisc.security.keycloak.iam.service.CustomService;
import jakarta.annotation.PostConstruct;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;

import java.util.Collections;
import java.util.List;


public class CustomUserServiceProviderFactory implements
        UserStorageProviderFactory<CustomUserServiceProvider> {

    private static final Logger logger = Logger.getLogger(CustomUserServiceProviderFactory.class);

    public static CustomService customService;

    @Override
    public CustomUserServiceProvider create(KeycloakSession session, ComponentModel model) {
        if(customService == null) {
            CustomUserServiceProviderFactory.customService = new CustomService();
            CustomUserServiceProviderFactory.customService.init();
        }
        return new CustomUserServiceProvider(session,model,customService);
    }

    @Override
    public String getId() {
        return "custom-iam-user-service";
    }

    @Override
    public void close() {
        logger.info("custom iam User Service Provider Factory closed.");
    }


    @Override
    public void init(Config.Scope config) {

        logger.info("Initializing iam User Service Provider Factory");
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }


}
