package com.modernisc.security.keycloak.iam.service;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializer;
import com.modernisc.security.keycloak.iam.kc.KeycloakToken;
import com.modernisc.security.keycloak.iam.dto.*;
import com.modernisc.security.keycloak.iam.util.*;
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
import org.springframework.http.HttpStatus;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.wildfly.security.util.PasswordBasedEncryptionUtil;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.MessageFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Objects;

import static com.modernisc.security.keycloak.iam.util.ExceptionUtil.getChainCauseMessage;

public class CustomService {

    private static final Logger LOGGER = Logger.getLogger(CustomService.class);
    private static final Logger SECURITY_LOGGER = Logger.getLogger("com.modernisc.security.log");

    private KeycloakToken ticket;
    private String customUrl;
    private String truststore_password;
    private String keystore_password;
    private String keystore_name;
    private String truststore_name;
    private String auth_server_url;
    private String auth_server_clientId;
    private String auth_server_clientSecret;

    public CustomService() {
        init();
    }

    public KeycloakToken getTicket() {
        return ticket;
    }

    public void setTicket(KeycloakToken ticket) {
        this.ticket = ticket;
    }

    public String getcustom_url() {
        return customUrl;
    }

    public void setcustom_url(String custom_url) {
        this.customUrl = custom_url;
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
            this.auth_server_url = QuarkusUtil.getProperty(("misc.iam.auth-server-url"));
        return auth_server_url;
    }

    public void setAuth_server_url(String auth_server_url) {
        this.auth_server_url = auth_server_url;
    }

    public String getAuth_server_clientId() {
        if(auth_server_clientId==null)
            this.auth_server_clientId = QuarkusUtil.getProperty(("misc.iam.auth-server-clientId"));
        return auth_server_clientId;
    }

    public void setAuth_server_clientId(String auth_server_clientId) {
        this.auth_server_clientId = auth_server_clientId;
    }

    public String getAuth_server_clientSecret() {
        if(auth_server_clientSecret==null)
            this.auth_server_clientSecret = QuarkusUtil.getProperty(("misc.iam.auth-server-clientSecret"));
        return auth_server_clientSecret;
    }

    public void setAuth_server_clientSecret(String auth_server_clientSecret) {
        this.auth_server_clientSecret = auth_server_clientSecret;
    }

    public void init() {
        LOGGER.info("init token ...");
        getToken();
    }


    private void getToken() {
        try {
            this.customUrl = QuarkusUtil.getProperty("misc.iam.url");
            this.truststore_password = new String(getUnmaskedPass(QuarkusUtil.getProperty("truststore-password")));
            this.keystore_password = new String(getUnmaskedPass(QuarkusUtil.getProperty("keystore-password")));
            this.keystore_name = QuarkusUtil.getProperty("keystore-name");
            this.truststore_name = QuarkusUtil.getProperty("truststore-name");
            this.auth_server_url = QuarkusUtil.getProperty("misc.iam.auth-server-url");
            this.auth_server_clientId = QuarkusUtil.getProperty("misc.iam.auth-server-clientId");
            this.setAuth_server_clientSecret ( new String(getUnmaskedPass(QuarkusUtil.getProperty("misc.iam.auth-server-clientSecret"))));
            if(this.ticket!=null) {
                this.ticket = refreshToken();
                return;
            }
            this.ticket = loginIntoOauthServer();
        } catch (GeneralSecurityException | IOException exp) {
            LOGGER.error(MessageFormat.format("Error in keycloak-app login into misc.iam. Message:{0}", getChainCauseMessage(exp)));
            SECURITY_LOGGER.error(MessageFormat.format("Error in keycloak-app login into misc.iam. Message:{0}", getChainCauseMessage(exp)));
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
        String configDir = QuarkusUtil.getProperty("quarkus-home-dir") + "/ssl";

        File trustStore = new File(configDir + File.separator + getTruststore_name());
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(new File(configDir + File.separator + getKeystore_name())),
                getKeystore_password().toCharArray());

        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(
                new SSLContextBuilder()
                        .loadTrustMaterial(trustStore, getTruststore_password().toCharArray())
                        .loadKeyMaterial(keyStore, getKeystore_password().toCharArray())
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

    public KeycloakToken loginIntoOauthServer() throws IOException, GeneralSecurityException {
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
        KeycloakToken response = gson.fromJson(body1, KeycloakToken.class);

        client.close();

        int code = httpResponse.getStatusLine().getStatusCode();
        if (code == 200) {
            return response;
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
    private String getStoredRefreshToken(){
        return ticket.getRefresh_token();
    }
    public KeycloakToken refreshToken() throws IOException, GeneralSecurityException {
        if(ticket==null)
            return loginIntoOauthServer();

        CloseableHttpClient client = getClient();
        HttpPost httpPost = new HttpPost(getAuth_server_url());

        // تغییر grant_type و اضافه کردن refresh_token
        String body = "client_id=" + getAuth_server_clientId()
                + "&client_secret=" + getAuth_server_clientSecret()
                + "&grant_type=refresh_token"
                + "&refresh_token=" + getStoredRefreshToken(); // متدی که توکن رفرش ذخیره شده را برمی‌گرداند

        StringEntity entity = new StringEntity(body);
        httpPost.setEntity(entity);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/x-www-form-urlencoded");

        CloseableHttpResponse httpResponse = client.execute(httpPost);
        InputStream content = httpResponse.getEntity().getContent();
        String body1 = IOUtils.toString(content, "UTF-8");

        KeycloakToken response = gson.fromJson(body1, KeycloakToken.class);
        client.close();

        int code = httpResponse.getStatusLine().getStatusCode();
        if (code == 200) {
            return response;
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
    public GetAuthenticateScyUserResult userLogin(String username, String password) throws IOException, GeneralSecurityException {
        GetAuthenticateScyUserRequest request = new GetAuthenticateScyUserRequest();
        request.setUsername(username);
        request.setPassword(password);
        try {
            GetAuthenticateScyUserResult result = callWithError("/authenticateScyUser", request, GetAuthenticateScyUserResult.class);
            return result;
        }catch (UnauthenticatedException exception){
            LOGGER.error(MessageFormat.format("custom>>Error in user login. {0}", exception));
            GetAuthenticateScyUserResult result = new GetAuthenticateScyUserResult();
            result.setAuthenticated(String.valueOf(false));
            return result;

        } catch (KeycloakException error) {
            if (error.getApiError().getCode().equals("EA20007")) {
                GetAuthenticateScyUserResult result = new GetAuthenticateScyUserResult();
                result.setAuthenticated(String.valueOf(true));
                return result;
            } else {
                GetAuthenticateScyUserResult result = new GetAuthenticateScyUserResult();
                result.setAuthenticated(String.valueOf(false));
                return result;
            }

        } catch (Exception exc) {
            LOGGER.error(MessageFormat.format("custom>>Error in user login. {0}", exc));
            setTicket(null);
            GetAuthenticateScyUserResult result = callWithError("/authenticateScyUser", request,
                    GetAuthenticateScyUserResult.class);

            return result;
        }
    }

    public UserInfo getUserByUsername(String username) throws GeneralSecurityException, IOException {
        GetUserByUsernameRequest request = new  GetUserByUsernameRequest();
        request.setUserName(username);
        GetUserByUsernameResult result  = callCustomService("/getUserByUsername", request, GetUserByUsernameResult.class);
        return result==null ? null : result.getUser();
    }

    public GetUsersCountResult getUsersCount() throws GeneralSecurityException, IOException {
        GetUsersCountRequest request = new  GetUsersCountRequest();
        return callCustomService("/getUsersCount", request, GetUsersCountResult.class);
    }

    public GetAllUsersResult getAllUsers(int firstResult, int maxResults) throws GeneralSecurityException, IOException {
        GetAllUsersRequest request = new  GetAllUsersRequest();
        request.setFirstResult(firstResult);
        request.setMaxResults(maxResults);
        return callCustomService("/getAllUsers", request, GetAllUsersResult.class);
    }

    public GetSearchForUserResult searchForUser(String search, int firstResult, int maxResults) throws GeneralSecurityException, IOException {
        GetSearchForUserRequest request = new  GetSearchForUserRequest();
        request.setSearch(search);
        request.setFirstResult(firstResult);
        request.setMaxResults(maxResults);
        return callCustomService("/searchForUser", request, GetSearchForUserResult.class);
    }
    public GetSearchForUserResult searchForUserStream(Map<String, String> params, int firstResult, int maxResults) throws GeneralSecurityException, IOException {
        GetSearchForUserRequest request = new  GetSearchForUserRequest();
        request.setSearch(params.get("search"));
        request.setFirstResult(firstResult);
        request.setMaxResults(maxResults);
        return callCustomService("/searchForUser", request, GetSearchForUserResult.class);
    }
    public GetUserRoleSetResult getUserRoleSet(long userId) throws GeneralSecurityException, IOException {
        GetUserRoleSetRequest request = new  GetUserRoleSetRequest();
        request.setUserId(String.valueOf(userId));
        return callCustomService("/getUserRoleSet", request, GetUserRoleSetResult.class);
    }

    public UserInfo getUserById(BigDecimal persistenceId) throws GeneralSecurityException, IOException {
        GetUserByIdRequest request = new  GetUserByIdRequest();
        request.setPersistenceId(persistenceId.longValue());
        GetUserByIdResult result = callCustomService("/getUserById", request, GetUserByIdResult.class);
        return result==null ? null : result.getUser();
    }

    public <T, R> T callCustomService(String methodUrl, R request, Class<T> responseType) throws GeneralSecurityException, IOException {
        try {
            return callWithError(methodUrl, request, responseType);
        } catch (UnauthenticatedException e){
            if( Objects.equals(e.getErrorCode(),"misc.exceptions.security.3003") &&
                    !Objects.equals(methodUrl,"/authenticateScyUser" ) ){
                this.ticket = refreshToken();
                return callWithError(methodUrl, request, responseType);
            }
            return null;
        }
        catch (RuntimeException exc) {
            LOGGER.error("misc.iam>>"+exc.getMessage(), exc);
            return null;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
    private final Gson gson = new GsonBuilder()
            .registerTypeAdapter(LocalDateTime.class,
                    (JsonDeserializer<LocalDateTime>) (json, type, ctx) ->
                            LocalDateTime.parse(json.getAsString(), DateTimeFormatter.ISO_LOCAL_DATE_TIME))
            .registerTypeAdapter(LocalDate.class,
                    (JsonDeserializer<LocalDate>) (json, type, ctx) ->
                            LocalDate.parse(json.getAsString(), DateTimeFormatter.ISO_LOCAL_DATE))
            .create();

    public <T, R> T callWithError(String methodUrl, R request, Class<T> responseType)
            throws GeneralSecurityException, IOException {
        try {
            CloseableHttpClient client = getClient();
            HttpPost httpPost = new HttpPost(getcustom_url() + methodUrl);
            String json = gson.toJson(request);

            StringEntity entity = new StringEntity(json);
            httpPost.setEntity(entity);
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");
            KeycloakToken ticket = getTicket();

            if (ticket == null) {
                this.ticket = loginIntoOauthServer();
                ticket = this.ticket;
            }

            httpPost.setHeader("Authorization", "Bearer " + ticket.getAccess_token());

            CloseableHttpResponse httpResponse = client.execute(httpPost);
            InputStream content = httpResponse.getEntity().getContent();

            String body = IOUtils.toString(content, "UTF-8");

            T response = gson.fromJson(body, responseType);

            client.close();

            int code = httpResponse.getStatusLine().getStatusCode();
            if (code == 200) {
                return response;
            } else if (code == 401) {
                LOGGER.error(MessageFormat.format("Error message:{0}, {1}", httpResponse.toString(), body));
                SECURITY_LOGGER.error(MessageFormat.format("Error message:{0}, {1}", httpResponse.toString(), body));
                this.setTicket(null);
                throw new UnauthenticatedException();
            } else if (code == 403) {
                LOGGER.error(MessageFormat.format("Error message:{0}, {1}", httpResponse.toString(), body));
                SECURITY_LOGGER.error(MessageFormat.format("Error message:{0}, {1}", httpResponse.toString(), body));
                //this.setTicket(null);
                throw new ForbiddenException();
            } else {
                ApiError fault = gson.fromJson(body, ApiError.class);
                this.setTicket(null);

                LOGGER.error(MessageFormat.format("Error in keycloak-app, calling misc.iam. Message:{0}", body));
                SECURITY_LOGGER.error(MessageFormat.format("Error in keycloak-app, calling misc.iam. Message:{0}", body));

                if (fault.getStatus() != HttpStatus.OK) {
                    throw new KeycloakException(fault);
                }
                this.ticket = loginIntoOauthServer();
                return null;
            }
        } catch (Exception exception) {
            LOGGER.error(MessageFormat.format("custom>>Error when call customService. {0}", exception));
            throw exception;
        }
    }

}
