package com.misc.bis.security;

import com.misc.bis.security.util.ExceptionUtil;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.jboss.logging.MDC;
import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.jpa.ClientAdapter;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.util.BasicAuthHelper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.MessageFormat;
import java.util.*;

public class NakisaClientIdAndSecretCredentialsProviderFactory extends ClientIdAndSecretAuthenticator {

    private static final Logger logger = Logger.getLogger(NakisaClientIdAndSecretCredentialsProviderFactory.class);
    private static final Logger SECURITY_LOGGER = Logger.getLogger("com.modernisc.security.log");

    private KeycloakSession session;

    @Override
    public String getDisplayType() {
        return "Nakisa Client Secret Authenticator";
    }

    @Override
    public ClientAuthenticator create(KeycloakSession keycloakSession) {
        this.session = keycloakSession;
        return this;
    }

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {

        MDC.put("ip", context.getConnection().getRemoteAddr());

        try {
            super.authenticateClient(context);
            if(context.getStatus().equals(FlowStatus.FAILED)){
                validateHashedSecretKey(context);
            }
        } finally {
            MDC.remove("ip");
        }
    }

    private void validateHashedSecretKey(ClientAuthenticationFlowContext context){

        // following codes Copied from super class implementation, in case of any upgrade please check implementation of new version again!
        // ************************************ copied from super class - begin ***********************************************************
        String clientId = null;
        String clientSecret = null;
        HttpRequest request = context.getHttpRequest();
        String authorizationHeader = request.getHttpHeaders().getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        MediaType mediaType = context.getHttpRequest().getHttpHeaders().getMediaType();
        boolean hasFormData = mediaType != null && mediaType.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        MultivaluedMap<String, String> formData = hasFormData ? context.getHttpRequest().getDecodedFormParameters() : null;
        if (authorizationHeader != null) {
            String[] usernameSecret = BasicAuthHelper.RFC6749.parseHeader(authorizationHeader);
            if (usernameSecret != null) {
                clientId = usernameSecret[0];
                clientSecret = usernameSecret[1];
            } else {

                // Don't send 401 if client_id parameter was sent in request. For example IE may automatically send "Authorization: Negotiate" in XHR requests even for public clients
                if (formData != null && !formData.containsKey(OAuth2Constants.CLIENT_ID)) {
                    Response challengeResponse = Response.status(Response.Status.UNAUTHORIZED).header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"" + context.getRealm().getName() + "\"").build();
                    context.challenge(challengeResponse);
                    return;
                }
            }
        }
        if (formData != null) {
            if (formData.containsKey(OAuth2Constants.CLIENT_ID)) {
                clientId = formData.getFirst(OAuth2Constants.CLIENT_ID);
            }
            if (formData.containsKey(OAuth2Constants.CLIENT_SECRET)) {
                clientSecret = formData.getFirst(OAuth2Constants.CLIENT_SECRET);
            }
        }
        if (clientId == null) {
            clientId = context.getSession().getAttribute("client_id", String.class);
        }
        ClientModel client = context.getSession().clients().getClientByClientId(context.getRealm(), clientId);
        if(client==null) {
            logger.error(MessageFormat.format( "Error : clientId {0} not in realm {1} " ,clientId, context.getRealm().getName()));
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }
        // ************************************ copied from super class - end *************************************************************

        String expectedHash;
        String clientIdHash;
        try {
            clientIdHash = sha256(clientId + "-" + context.getRealm().getId());
            expectedHash = sha256(clientIdHash + "-" + clientSecret);
            if (!expectedHash.equals(client.getSecret())) {
                Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "unauthorized_client", "[CNFG-004]: client_secret hash mismatch");
                context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challengeResponse);
            } else {
                context.success();
            }
        } catch (Exception exp) {
            logger.error("Error in Hash calculating: " + ExceptionUtil.getChainCauseMessage(exp));
        }
    }

    public static String sha256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
