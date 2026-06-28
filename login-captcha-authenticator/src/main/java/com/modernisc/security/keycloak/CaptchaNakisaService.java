package com.modernisc.security.keycloak;

import com.google.gson.Gson;
import com.modernisc.security.keycloak.dto.GetUserByUsernameRequest;
import com.modernisc.security.keycloak.dto.GetUserByUsernameResult;
import com.modernisc.security.keycloak.dto.UserInfo;
import com.modernisc.security.keycloak.util.QuarkusUtil;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.jboss.logging.Logger;
import org.wildfly.security.util.PasswordBasedEncryptionUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.text.MessageFormat;

import static com.modernisc.security.keycloak.util.ExceptionUtil.getChainCauseMessage;

public class CaptchaNakisaService {

    private static final Logger LOGGER = Logger.getLogger(CaptchaNakisaService.class);
    private static final Logger SECURITY_LOGGER = Logger.getLogger("com.modernisc.security.log");
    private String ticket;
    private String nakisa_url;
    private String truststore_password;
    private String keystore_password;
    private String keystore_name;
    private String truststore_name;
    private String auth_server_url;
    private String auth_server_clientId;
    private String auth_server_clientSecret;

    public CaptchaNakisaService() {
    }

    public String getTicket() {
        return ticket;
    }

    public void setTicket(String ticket) {
        this.ticket = ticket;
    }

    public String getNakisa_url() {
        if(nakisa_url==null)
            this.nakisa_url = QuarkusUtil.getProperty(("nakisa-url"));
        return nakisa_url;
    }

    public void setNakisa_url(String nakisa_url) {
        this.nakisa_url = nakisa_url;
    }

    public String getTruststore_password() throws GeneralSecurityException {
        if(truststore_password==null)
            this.truststore_password = new String(getUnmaskedPass(QuarkusUtil.getProperty(("truststore-password"))));

        return truststore_password;
    }

    public void setTruststore_password(String truststore_password) {
        this.truststore_password = truststore_password;
    }

    public String getKeystore_password() throws GeneralSecurityException {
        if(keystore_password==null)
            this.keystore_password = new String(getUnmaskedPass(QuarkusUtil.getProperty(("keystore-password"))));

        return keystore_password;
    }

    public void setKeystore_password(String keystore_password) {
        this.keystore_password = keystore_password;
    }

    public String getKeystore_name() {
        if(keystore_name==null)
            this.keystore_name = QuarkusUtil.getProperty(("keystore-name"));
        return keystore_name;
    }

    public void setKeystore_name(String keystore_name) {
        this.keystore_name = keystore_name;
    }

    public String getTruststore_name() {
        if(truststore_name==null)
            this.truststore_name = QuarkusUtil.getProperty(("truststore-name"));
        return truststore_name;
    }

    public void setTruststore_name(String truststore_name) {
        this.truststore_name = truststore_name;
    }

    public String getAuth_server_url() {
        if(auth_server_url==null)
            this.auth_server_url = QuarkusUtil.getProperty(("auth-server-url"));
        return auth_server_url;
    }

    public void setAuth_server_url(String auth_server_url) {
        this.auth_server_url = auth_server_url;
    }

    public String getAuth_server_clientId() {
        if(auth_server_clientId==null)
            this.auth_server_clientId = QuarkusUtil.getProperty(("auth-server-clientId"));
        return auth_server_clientId;
    }

    public void setAuth_server_clientId(String auth_server_clientId) {
        this.auth_server_clientId = auth_server_clientId;
    }

    public String getAuth_server_clientSecret() throws GeneralSecurityException {
        if(auth_server_clientSecret==null)
            this.auth_server_clientSecret = new String(getUnmaskedPass(QuarkusUtil.getProperty(("auth-server-clientSecret"))));

        return auth_server_clientSecret;
    }

    public void setAuth_server_clientSecret(String auth_server_clientSecret) {
        this.auth_server_clientSecret = auth_server_clientSecret;
    }
    public void getToken(){
        try {
            this.ticket = loginIntoOauthServer();
        } catch (IOException | GeneralSecurityException exp) {
            LOGGER.error(MessageFormat.format("Error in keycloak-app login into nakisa. Message:{0}", getChainCauseMessage(exp)));
            SECURITY_LOGGER.error(MessageFormat.format("Error in keycloak-app login into nakisa. Message:{0}", getChainCauseMessage(exp)));
        }
    }

    private char[] getUnmaskedPass(String maskedPassword) throws GeneralSecurityException {
        int maskLength = "MASK-".length();
        if (maskedPassword == null || maskedPassword.length() <= maskLength) {
            throw new GeneralSecurityException("Invalid masked password.");
        }
        String[] parsed = maskedPassword.substring(maskLength).split(";");
        if (parsed.length != 3) {
            throw new GeneralSecurityException();
        }
        String encoded = parsed[0];
        String salt = parsed[1];
        int iteration = Integer.parseInt(parsed[2]);
        PasswordBasedEncryptionUtil encryptUtil = new PasswordBasedEncryptionUtil.Builder().picketBoxCompatibility().salt(salt).iteration(iteration)
                .decryptMode().build();

        return encryptUtil.decodeAndDecrypt(encoded);
    }

    private CloseableHttpClient getClient() throws GeneralSecurityException, IOException {

        String truststore_password = new String(getUnmaskedPass(QuarkusUtil.getProperty("truststore-password")));
        String keystore_password = new String(getUnmaskedPass(QuarkusUtil.getProperty("keystore-password")));
        String keystore_name = QuarkusUtil.getProperty("keystore-name");
        String truststore_name = QuarkusUtil.getProperty("truststore-name");
        String configDir = QuarkusUtil.getProperty("quarkus-home-dir") + "/ssl";

        File trustStore = new File(configDir + File.separator + truststore_name);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(new File(configDir + File.separator + keystore_name)),
                keystore_password.toCharArray());

        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(
                new SSLContextBuilder()
                        .loadTrustMaterial(trustStore, truststore_password.toCharArray())
                        .loadKeyMaterial(keyStore, keystore_password.toCharArray())
                        .build());
        Registry<ConnectionSocketFactory> socketFactoryRegistry =
                RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("https", socketFactory)
                        .register("http", new PlainConnectionSocketFactory())
                        .build();
        BasicHttpClientConnectionManager connectionManager =
                new BasicHttpClientConnectionManager(socketFactoryRegistry);
        CloseableHttpClient client = HttpClients.custom()
                .setSSLSocketFactory(socketFactory)
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .setConnectionManager(connectionManager).build();
        return client;
    }

    /**
     * Makes a request to keycloak server at address {@code auth-server-url} for getting an access-token to call Nakisa's keycloak services.
     *
     * @return String An access-token
     * @throws IOException Throws IOException if it can not find /ssl folder under keycloak installation directory
     * @throws GeneralSecurityException
     */
    public String loginIntoOauthServer() throws IOException, GeneralSecurityException {
        String auth_server_url = QuarkusUtil.getProperty("auth-server-url");
        String auth_server_clientId = QuarkusUtil.getProperty("auth-server-clientId");
        String auth_server_clientSecret = new String(getUnmaskedPass(QuarkusUtil.getProperty("auth-server-clientSecret")));

        CloseableHttpClient client = getClient();
        HttpPost httpPost = new HttpPost(auth_server_url);
        String body = "client_id=" + auth_server_clientId + "&client_secret=" +  auth_server_clientSecret + "&grant_type=client_credentials";
        StringEntity entity = new StringEntity(body);
        httpPost.setEntity(entity);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/x-www-form-urlencoded");
        CloseableHttpResponse httpResponse = client.execute(httpPost);
        InputStream content = httpResponse.getEntity().getContent();

        String body1 = IOUtils.toString(content, "UTF-8");
        KeycloakToken response = new Gson().fromJson(body1, KeycloakToken.class);

        client.close();

        int code = httpResponse.getStatusLine().getStatusCode();
        if (code == 200) {
            return response.getAccess_token();
        } else if (code == 401) {
            LOGGER.error(MessageFormat.format("Client secret not provided in request or Invalid client secret. Message:{0}", response));
            SECURITY_LOGGER.error(MessageFormat.format("Client secret not provided in request or Invalid client secret. Message:{0}", response));
            this.setTicket(null);
            return null;
        } else if (code == 400) {
            LOGGER.error(MessageFormat.format("Missing form parameter: grant_type or Unsupported grant_type. Message:{0}", response));
            SECURITY_LOGGER.error(MessageFormat.format("Missing form parameter: grant_type or Unsupported grant_type. Message:{0}", response));
            this.setTicket(null);
            return null;
        } else {
            return null;
        }
    }

    public int getMaxTryCount(String username) throws GeneralSecurityException, IOException {
        GetUserByUsernameRequest request = new GetUserByUsernameRequest();
        request.setUserName(username);

        GetUserByUsernameResult result = callNakisa("/getUserByUsername", request, GetUserByUsernameResult.class);
        if (result == null || result.getUser() == null) {
            return -1;
        }
        return result.getUser().getMaxTryCount();
    }

    public boolean isUserCredentialExpired(String username) throws GeneralSecurityException, IOException {
        GetUserByUsernameRequest request = new GetUserByUsernameRequest();
        request.setUserName(username);
        GetUserByUsernameResult retValue = callNakisa("/getUserByUsername", request, GetUserByUsernameResult.class);
        if (retValue ==null || retValue.getUser() == null) {
            return false;
        }
        UserInfo userInfo = retValue.getUser();

        return Boolean.TRUE.equals(userInfo.isCredentialsExpired()) ||
                (userInfo.getPasswordExpirationDate() != null && userInfo.getPasswordExpirationDate().getTime() < System.currentTimeMillis());
    }

    public <T, R> T callNakisa(String methodUrl, R request, Class<T> responseType) throws GeneralSecurityException, IOException {
        try {
            return callNakisa_internal(methodUrl, request, responseType);
        }
        catch (RuntimeException | GeneralSecurityException exc){
            if ("Nakisa 401".equals(exc.getMessage())){
                LOGGER.info("Getting new token and retry");
                getToken();
                return callNakisa_internal(methodUrl, request, responseType);
            }

            LOGGER.error(exc.getMessage(), exc);
            return null;
        }
    }

    private <T, R> T callNakisa_internal(String methodUrl, R request, Class<T> responseType) throws GeneralSecurityException, IOException {
        String nakisa_url = QuarkusUtil.getProperty("nakisa-url");

        CloseableHttpClient client = getClient();
        HttpPost httpPost = new HttpPost(nakisa_url + methodUrl);
        String json = new Gson().toJson(request);

        StringEntity entity = new StringEntity(json);
        httpPost.setEntity(entity);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/json");
        String ticket = getTicket();
        if (ticket == null) {
            this.ticket = loginIntoOauthServer();
            ticket = getTicket();
        }
        httpPost.setHeader("Authorization", "Bearer " + ticket);

        CloseableHttpResponse httpResponse = client.execute(httpPost);
        InputStream content = httpResponse.getEntity().getContent();

        String body = IOUtils.toString(content, "UTF-8");
        T response = new Gson().fromJson(body, responseType);

        client.close();

        int code = httpResponse.getStatusLine().getStatusCode();
        if (code == 200) {
            return response;
        } else if (code == 401) {
            LOGGER.error(MessageFormat.format("Error message:{0}, {1}", httpResponse.toString(), body));
            SECURITY_LOGGER.error(MessageFormat.format("Error message:{0}, {1}", httpResponse.toString(), body));
            this.setTicket(null);

            throw new RuntimeException("Nakisa 401");
        } else if (code == 403) {
            LOGGER.error(MessageFormat.format("Error message:{0}, {1}", response, body));
            SECURITY_LOGGER.error(MessageFormat.format("Error message:{0}, {1}", response, body));
            this.setTicket(null);
            return null;
        } else if (code == 404) {
            LOGGER.error(MessageFormat.format("Error message:{0}, {1}", response, body));
            SECURITY_LOGGER.error(MessageFormat.format("Error message:{0}, {1}", response, body));
            return null;
        } else if (code == 500) {
            LOGGER.error(MessageFormat.format("Error message:{0}, {1}", response, body));
            SECURITY_LOGGER.error(MessageFormat.format("Error message:{0}, {1}", response, body));
            return null;
        } else {
            return null;
        }
    }

}
