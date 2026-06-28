package com.modernisc.security.keycloak;


import cn.apiclub.captcha.Captcha;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.jboss.logging.MDC;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.sessions.AuthenticationSessionModel;


import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;

import static com.modernisc.security.keycloak.util.ExceptionUtil.getChainCauseMessage;

public class CaptchaUsernamePasswordForm extends UsernamePasswordForm {

    private static final Logger logger = Logger.getLogger(CaptchaUsernamePasswordForm.class);
    private static final Logger SECURITY_LOGGER = Logger.getLogger("com.modernisc.security.log");
    private int userMaxTryCount = 0;

    private static CaptchaNakisaService nakisaService;

    public CaptchaUsernamePasswordForm() {
        if(nakisaService==null)
            nakisaService = new CaptchaNakisaService();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        MDC.put("ip", context.getConnection().getRemoteAddr());
        try {
            context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
            if (logger.isInfoEnabled()) {
                logger.info(
                        "validateCaptcha(AuthenticationFlowContext, boolean, String, String) - Before the validation");
            }

            // Get the configuration for this authenticator
            final AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();


            int maxTryCount = Integer.parseInt(configModel!=null && configModel.getConfig()!=null &&
                    configModel.getConfig().get(CaptchaUsernamePasswordFormFactory.MAX_TRY_COUNT)!=null ?
                    configModel.getConfig().get(CaptchaUsernamePasswordFormFactory.MAX_TRY_COUNT) : "0" );

            LoginFormsProvider form = context.form();
            if (context.getAuthenticationSession().getAuthNote("userMaxTryCount") != null) {
                userMaxTryCount = Integer.parseInt(context.getAuthenticationSession().getAuthNote("userMaxTryCount"));
            }

            if ((userMaxTryCount + 1) >= maxTryCount) {
                try {
                    Captcha captcha = MasterCaptchaManager.generateNewCaptcha();
                    context.getSession().getContext().getAuthenticationSession().setAuthNote("expectedCaptcha", captcha.getAnswer());
                    form.setAttribute("captchaImage", MasterCaptchaManager.captchaImageToString(captcha));
                    logger.info("captcha created.");
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
        }
        finally {
            MDC.remove("ip");
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MDC.put("ip", context.getConnection().getRemoteAddr());

        try {
            MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
            String username = formData.getFirst("username");
            try {
                userMaxTryCount = nakisaService.getMaxTryCount(username);
                if (userMaxTryCount == -1) {
                    throw new NoSuchAlgorithmException();
                }
            } catch (IOException exp) {
                logger.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", username, getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", username, getChainCauseMessage(exp)));
                Response challengeResponse = this.invalidCaptcha(context, "core_connection_failed");
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
                context.clearUser();
                authenticate(context);
                return;
            } catch (GeneralSecurityException exp) {
                logger.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", username, getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", username, getChainCauseMessage(exp)));
            }
            context.getAuthenticationSession().setAuthNote("userMaxTryCount", String.valueOf(userMaxTryCount));
            String requiredCaptcha = context.getAuthenticationSession().getAuthNote("requiredCaptcha");

            // checking the expired password
            Boolean isUserCredentialExpired = null;
            try {
                isUserCredentialExpired = nakisaService.isUserCredentialExpired(username);
            } catch (IOException | GeneralSecurityException exp) {
                logger.error(MessageFormat.format("Error in keycloak-app login into nakisa. Message:{0}", getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("Error in keycloak-app login into nakisa. Message:{0}", getChainCauseMessage(exp)));
            }

            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            if (isUserCredentialExpired) {
                context.getAuthenticationSession().setAuthNote("expiredPasswordFlag", "true");
                authSession.setUserSessionNote("expiredPasswordFlag", "true");
            } else {
                context.getAuthenticationSession().setAuthNote("expiredPasswordFlag", "false");
                authSession.setUserSessionNote("expiredPasswordFlag", "false");
            }

            if (requiredCaptcha != null && requiredCaptcha.equals("true")) {
                if (logger.isDebugEnabled()) {
                    logger.debug("action(AuthenticationFlowContext) - start");
                }

                String givenCaptcha = formData.getFirst("givenCaptcha");
                String expectedCaptcha = context.getSession().getContext().getAuthenticationSession().getAuthNote("expectedCaptcha");
                context.getSession().getContext().getAuthenticationSession().removeAuthNote("expectedCaptcha");

                if (expectedCaptcha == null || !expectedCaptcha.equals(givenCaptcha)) {
                    Response challengeResponse = this.invalidCaptcha(context, "invalid_captcha");
                    context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
                    context.clearUser();
                    //context.cancelLogin();
                    // reauthenticate....
                    authenticate(context);
                    return;
                }

                super.action(context);

                if (context.getStatus() != FlowStatus.SUCCESS) {
                    authenticate(context);
                }
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

    protected Response invalidCaptcha(AuthenticationFlowContext context, String messageKey) {
        return (Response) context.form().setError(messageKey, new Object[0]).createLoginUsernamePassword();
    }
}
