package com.modernisc.security.keycloak.users.cbank;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProviderFactory;

public class AbisUserStorageProviderFactory implements UserStorageProviderFactory<AbisUserStorageProvider> {

    private static final Logger logger = Logger.getLogger(AbisUserStorageProviderFactory.class);

    @Override
    public AbisUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        try {
            AbisUserStorageProvider provider = new AbisUserStorageProvider(model,session);
            /*InitialContext ctx = new InitialContext();
            AbisUserStorageProvider provider = (AbisUserStorageProvider)ctx
                    .lookup("java:global/user-storage-jpa-3.0.0-SNAPSHOT/" +
                            AbisUserStorageProvider.class.getSimpleName());
            provider.setModel(model);
            provider.setSession(session);*/
            provider.setModel(model);
            provider.setSession(session);
            if(AbisUserStorageProvider.nakisaService == null) {
                AbisUserStorageProvider.nakisaService = new NakisaService();
                AbisUserStorageProvider.nakisaService.init();

            }
            return provider;
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getId() {
        return "abis-user-storage-jpa";
    }

    @Override
    public String getHelpText() {
        return "ABIS User Storage Provider";
    }

    @Override
    public void close() {
        logger.debug("User storage closed");
    }
}
