package com.modernisc.security.keycloak;

import java.util.Arrays;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Defines plugins' factory and a new configuration attribute called "maxTryCount" that specifies maximum possible failed
 * login attempts for a user before keycloak blocks her.
 */
public class CaptchaUsernamePasswordFormFactory extends UsernamePasswordFormFactory {

    public static final String PROVIDER_ID = "captcha-u-p-form";
    /**
     * maxTryCount is the attribute that must be initialized after adding "Captcha Username Password Form" step to the
     * copied browser flow.
     */
    public static final String MAX_TRY_COUNT = "maxTryCount";
    private static CaptchaUsernamePasswordForm SINGLTONE;

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        if(SINGLTONE==null) {
            SINGLTONE = new CaptchaUsernamePasswordForm();
            System.out.println("CaptchaUsernamePasswordFormFactory  has been created");
        }
        return SINGLTONE;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return UserCredentialModel.PASSWORD;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }
    
    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Captcha Username Password Form";
    }

    @Override
    public String getHelpText() {
        return "Validates a username and password from login form + captcha";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty maxTryCount = new ProviderConfigProperty(
                MAX_TRY_COUNT,
                "Maximum try count for each user",
                "Specifies maximum try count for each user",
                ProviderConfigProperty.STRING_TYPE,
                "1");

        return Arrays.asList(maxTryCount);
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

}