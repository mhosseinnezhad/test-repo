package com.modernisc.security.keycloak.realms.master;


import cn.apiclub.captcha.Captcha;
import org.jboss.logging.Logger;
import org.jboss.logging.MDC;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;

import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Details;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;

import java.io.IOException;

import static com.modernisc.security.keycloak.util.ExceptionUtil.getChainCauseMessage;


public class CaptchaMasterUsernamePasswordForm extends UsernamePasswordForm {
    private static final Logger logger = Logger.getLogger(CaptchaMasterUsernamePasswordFormFactory.class);

    public CaptchaMasterUsernamePasswordForm() {
    }

    private int userMaxTryCount = 0;

    @Override
    public void authenticate(AuthenticationFlowContext context) {


        MDC.put("ip", context.getConnection().getRemoteAddr());

        try {
            context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
            if (logger.isInfoEnabled()) {
                logger.info("validateCaptcha(AuthenticationFlowContext, boolean, String, String) - Before the validation");
            }

            // Get the configuration for this authenticator
            final AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();


            int maxTryCount = Integer.parseInt(configModel != null && configModel.getConfig() != null &&
                    configModel.getConfig().get(CaptchaMasterUsernamePasswordFormFactory.MAX_TRY_COUNT) != null ?
                    configModel.getConfig().get(CaptchaMasterUsernamePasswordFormFactory.MAX_TRY_COUNT) : "0");

            LoginFormsProvider form = context.form();
            if (context.getAuthenticationSession().getAuthNote("userMaxTryCount") != null) {
                userMaxTryCount = Integer.parseInt(context.getAuthenticationSession().getAuthNote("userMaxTryCount"));
            }

            if ((userMaxTryCount + 1) >= maxTryCount) {
                try {
                    Captcha captcha = MasterCaptchaManager.generateNewCaptcha();
                    context.getSession().getContext().getAuthenticationSession().setAuthNote("expectedCaptcha", captcha.getAnswer());
                    context.form().setAttribute("captchaImage", MasterCaptchaManager.captchaImageToString(captcha));
                } catch (IOException exp) {
                    logger.error("captcha encryption error: " + getChainCauseMessage(exp));
                }

                context.getAuthenticationSession().setAuthNote("requiredCaptcha", "true");
                form.setAttribute("captchaRequired", true);
            } else {
                context.getAuthenticationSession().setAuthNote("requiredCaptcha", "false");
                form.setAttribute("captchaRequired", false);
                form.setAttribute("captcha", "");
                form.setAttribute("captchaImage", "");
            }
            super.authenticate(context);

        } finally {
            MDC.remove("ip");
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {

        MDC.put("ip", context.getConnection().getRemoteAddr());

        try {
            MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
            String givenCaptcha = formData.getFirst("givenCaptcha");

            String expectedCaptcha = context.getSession().getContext().getAuthenticationSession().getAuthNote("expectedCaptcha");
            context.getSession().getContext().getAuthenticationSession().removeAuthNote("expectedCaptcha");

            if (expectedCaptcha == null || !expectedCaptcha.equals(givenCaptcha)) {
                Response challengeResponse = this.invalidCaptcha(context);
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
                context.clearUser();
                //context.cancelLogin();
                // reauthenticate....
                authenticate(context);
                logger.error("expected captcha is null");
                return;
            }

            super.action(context);

            if (context.getStatus() != FlowStatus.SUCCESS) {
                authenticate(context);
            } else {
                super.action(context);

                if (context.getStatus() != FlowStatus.SUCCESS) {
                    authenticate(context);
                }
            }
        } finally {
            MDC.remove("ip");
        }
    }

    protected Response invalidCaptcha(AuthenticationFlowContext context) {
        return (Response) context.form().setError("invalid_captcha", new Object[0]).createLoginUsernamePassword();
    }
}
