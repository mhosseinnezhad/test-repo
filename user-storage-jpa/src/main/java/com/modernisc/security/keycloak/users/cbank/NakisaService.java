package com.modernisc.security.keycloak.users.cbank;

import com.google.gson.Gson;
import com.modernisc.nakisa.common.NakisaError;
import com.modernisc.nakisa.common.NakisaFault;
import com.modernisc.security.keycloak.users.cbank.dto.*;
import com.modernisc.security.keycloak.users.cbank.dto.*;
import com.modernisc.security.keycloak.users.cbank.util.QuarkusUtil;
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
import java.math.BigDecimal;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.MessageFormat;
import java.util.Map;

import static com.modernisc.security.keycloak.users.cbank.util.ExceptionUtil.getChainCauseMessage;


public class NakisaService {

    private static final Logger LOGGER = Logger.getLogger(NakisaService.class);
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

    public NakisaService() {
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
        //if(auth_server_clientSecret==null)
        this.auth_server_clientSecret = new String(getUnmaskedPass(QuarkusUtil.getProperty(("auth-server-clientSecret"))));
        return auth_server_clientSecret;
    }

    public void setAuth_server_clientSecret(String auth_server_clientSecret) {
        this.auth_server_clientSecret = auth_server_clientSecret;
    }

    public void init(){
        try {
            getToken();
        }catch (Exception e){
            LOGGER.error("token for keycloak-app not retrieved."+ e);
        }
    }

    private void getToken() throws GeneralSecurityException {
        this.nakisa_url = QuarkusUtil.getProperty(("nakisa-url"));
        this.truststore_password = new String(getUnmaskedPass(QuarkusUtil.getProperty(("truststore-password"))));
        this.keystore_password = new String(getUnmaskedPass(QuarkusUtil.getProperty(("keystore-password"))));
        this.keystore_name = QuarkusUtil.getProperty(("keystore-name"));
        this.truststore_name = QuarkusUtil.getProperty(("truststore-name"));
        this.auth_server_url = QuarkusUtil.getProperty(("auth-server-url"));
        this.auth_server_clientId = QuarkusUtil.getProperty(("auth-server-clientId"));
        this.auth_server_clientSecret = new String(getUnmaskedPass(QuarkusUtil.getProperty(("auth-server-clientSecret"))));

        try {
            this.ticket = loginIntoOauthServer();
            LOGGER.info("retrieved ticket for nakisa service.");
        } catch (IOException | GeneralSecurityException exp) {
            LOGGER.error(MessageFormat.format("Error in keycloak-app login into nakisa. Message:{0}", getChainCauseMessage(exp)));
            SECURITY_LOGGER.error(MessageFormat.format("Error in keycloak-app login into nakisa. Message:{0}", getChainCauseMessage(exp)));
        }
    }

    private char[] getUnmaskedPass(String maskedPassword) throws GeneralSecurityException {
        int maskLength = "MASK-".length();
        if (maskedPassword == null || maskedPassword.length() <= maskLength) {
            throw new GeneralSecurityException();
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

    private CloseableHttpClient getClient() throws GeneralSecurityException,
            IOException {

        String truststore_password = new String(getUnmaskedPass(QuarkusUtil.getProperty("truststore-password")));
        String keystore_password = new String(getUnmaskedPass(QuarkusUtil.getProperty("keystore-password")));
        String keystore_name = QuarkusUtil.getProperty("keystore-name");
        String truststore_name = QuarkusUtil.getProperty("truststore-name");
        String configDir = QuarkusUtil.getProperty("quarkus-home-dir") + "/ssl";

        File trustStore = new File(configDir + File.separator + truststore_name);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(new File(configDir + File.separator + keystore_name)), keystore_password.toCharArray());

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

    public String loginIntoOauthServer() throws IOException, GeneralSecurityException {
        CloseableHttpClient client = getClient();
        HttpPost httpPost = new HttpPost(getAuth_server_url());
        String body = "client_id=" + getAuth_server_clientId() + "&client_secret=" +  getAuth_server_clientSecret() + "&grant_type=client_credentials";
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

    public String userLogin(String username, String password) throws IOException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, CertificateException, UnrecoverableKeyException {
        GetAuthenticateScyUserRequest request = new GetAuthenticateScyUserRequest();
        request.setUsername(username);
        request.setPassword(password);
        try {
        GetAuthenticateScyUserResult result = callNakisaWithError("/authenticateScyUser", request, GetAuthenticateScyUserResult.class);
            return result.getAuthenticated();
        } catch (NakisaError nakisaError) {
            if (nakisaError.getCode().equals("EA20007")) {
                return "true";
            } else {
                return "false";
            }
        }
        catch (Exception exc){
            return "false";
        }
    }

    public UserInfo getUserByUsername(String username) throws GeneralSecurityException, IOException {
        GetUserByUsernameRequest request = new  GetUserByUsernameRequest();
        request.setUserName(username);
        GetUserByUsernameResult result  =callNakisa("/getUserByUsername", request, GetUserByUsernameResult.class);
        return result==null ? null : result.getUser();
    }

    public GetUsersCountResult getUsersCount() throws GeneralSecurityException, IOException {
        GetUsersCountRequest request = new  GetUsersCountRequest();
        return callNakisa("/getUsersCount", request, GetUsersCountResult.class);
    }

    public GetAllUsersResult getAllUsers(int firstResult, int maxResults) throws GeneralSecurityException, IOException {
        GetAllUsersRequest request = new  GetAllUsersRequest();
        request.setFirstResult(firstResult);
        request.setMaxResults(maxResults);
        return callNakisa("/getAllUsers", request, GetAllUsersResult.class);
    }

    public GetSearchForUserResult searchForUser(String search, int firstResult, int maxResults) throws GeneralSecurityException, IOException {
        GetSearchForUserRequest request = new  GetSearchForUserRequest();
        request.setSearch(search);
        request.setFirstResult(firstResult);
        request.setMaxResults(maxResults);
        return callNakisa("/searchForUser", request, GetSearchForUserResult.class);
    }

    public GetSearchForUserResult searchForUserStream(Map<String, String> params, int firstResult, int maxResults) throws GeneralSecurityException, IOException {
        GetSearchForUserRequest request = new  GetSearchForUserRequest();
        request.setSearch(params.get("search"));
        request.setFirstResult(firstResult);
        request.setMaxResults(maxResults);
        return callNakisa("/searchForUser", request, GetSearchForUserResult.class);
    }

    public GetUserRoleSetResult getUserRoleSet(long userId) throws GeneralSecurityException, IOException {
        GetUserRoleSetRequest request = new  GetUserRoleSetRequest();
        request.setUserId(String.valueOf(userId));
        return callNakisa("/getUserRoleSet", request, GetUserRoleSetResult.class);
    }

    public UserInfo getUserById(BigDecimal persistenceId) throws GeneralSecurityException, IOException {
        GetUserByIdRequest request = new  GetUserByIdRequest();
        request.setPersistenceId(persistenceId.longValue());
        return callNakisa("/getUserById", request, GetUserByIdResult.class).getUser();
    }

    public <T, R> T callNakisa(String methodUrl, R request, Class<T> responseType) throws GeneralSecurityException, IOException {
        try {
            return callNakisaWithError(methodUrl, request, responseType);
        } catch (RuntimeException | GeneralSecurityException exc) {
            if ("Nakisa 401".equals(exc.getMessage())) {
                LOGGER.info("Getting new token and retry");
                getToken();
                return callNakisaWithError(methodUrl, request, responseType);
            }
            LOGGER.error(exc.getMessage(), exc);
            return null;
        }
    }

    public <T, R> T callNakisaStream(String methodUrl, R request, Class<T> responseType) throws GeneralSecurityException, IOException {
        try {
            return callNakisaWithError(methodUrl, request, responseType);
        } catch (RuntimeException | GeneralSecurityException exc) {
            if ("Nakisa 401".equals(exc.getMessage())) {
                return callNakisaWithError(methodUrl, request, responseType);
            }
            LOGGER.error(exc.getMessage(), exc);
            return null;
        }
    }

    public <T, R> T callNakisaWithError(String methodUrl, R request, Class<T> responseType) throws GeneralSecurityException, IOException {
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
            if(ticket==null) {
                LOGGER.error(MessageFormat.format("Client secret not provided in request or Invalid client secret. clientid ={0} ", auth_server_clientId));
                SECURITY_LOGGER.error(MessageFormat.format("Client secret not provided in request or Invalid client secret. clientid ={0} ", auth_server_clientId));
                throw new RuntimeException("Nakisa 401");
            }

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
        } else {
            NakisaFault nakisaFault = new Gson().fromJson(body, NakisaFault.class);
            this.setTicket(null);

            LOGGER.error(MessageFormat.format("Error in keycloak-app, calling nakisa. Message:{0}", body));
            SECURITY_LOGGER.error(MessageFormat.format("Error in keycloak-app, calling nakisa. Message:{0}", body));

            if (nakisaFault.getCode() != null) {
                throw new NakisaError(nakisaFault.getMessage(), nakisaFault);
            }
            this.ticket = loginIntoOauthServer();
            return null;
        }
    }

}
