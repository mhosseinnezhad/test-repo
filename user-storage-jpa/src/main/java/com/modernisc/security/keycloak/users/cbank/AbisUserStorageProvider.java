package com.modernisc.security.keycloak.users.cbank;

import com.modernisc.security.keycloak.users.cbank.dto.GetSearchForUserResult;
import com.modernisc.security.keycloak.users.cbank.dto.GetUsersCountResult;
import com.modernisc.security.keycloak.users.cbank.dto.UserInfo;
import org.jboss.logging.Logger;
import org.jboss.logging.MDC;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.OnUserCache;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

import java.io.IOException;
import java.math.BigDecimal;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.MessageFormat;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static com.modernisc.security.keycloak.users.cbank.util.ExceptionUtil.getChainCauseMessage;



public class AbisUserStorageProvider implements UserStorageProvider,
        UserLookupProvider,
        UserRegistrationProvider,
        UserQueryProvider,
        CredentialInputUpdater,
        CredentialInputValidator,
        OnUserCache {

    private static final Logger LOGGER = Logger.getLogger(AbisUserStorageProvider.class);
    private static final Logger SECURITY_LOGGER = Logger.getLogger("com.modernisc.security.log");

    public static final String PASSWORD_CACHE_KEY = UserAdapter.class.getName() + ".password";

    protected ComponentModel model;
    protected KeycloakSession session;

    /*@Inject*/
    public static NakisaService nakisaService = null;

    public AbisUserStorageProvider(ComponentModel model, KeycloakSession session) {
        this.model = model;
        this.session = session;

    }
    public void setModel(ComponentModel model) {
        LOGGER.info("\r\r\n ----- setModel in AbisUserStorageProvider ----- > > > " + model.toString());
        this.model = model;
    }

    public void setSession(KeycloakSession session) {
        LOGGER.info("\r\r\n ----- setSession in AbisUserStorageProvider----- > > > " + session.toString());
        this.session = session;
    }
    @Override
    public boolean supportsCredentialType(String credentialType) {
        return CredentialModel.PASSWORD.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType) && getPassword(user) != null;
    }

    private String getPassword(UserModel user) {
        String password = null;
        if (user instanceof CachedUserModel) {
            password = (String) ((CachedUserModel) user).getCachedWith().get(PASSWORD_CACHE_KEY);
        } else if (user instanceof UserAdapter) {
            password = ((UserAdapter) user).getPassword();
        }
        return password;
    }

    private <T> T doInLoggingProvider(KeycloakSession session, Supplier<T> method) {
        MDC.put("ip", session.getContext().getConnection().getRemoteAddr());

        try{
            return method.get();
        }
        finally {
            MDC.remove("ip");
        }
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        return doInLoggingProvider(session, ()-> {
            String password = credentialInput.getChallengeResponse();
            String status = null;
            try {
                status = nakisaService.userLogin(user.getUsername(), password);
            } catch (IOException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException | CertificateException | UnrecoverableKeyException exp) {
                LOGGER.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", user.getUsername(), getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", user.getUsername(), getChainCauseMessage(exp)));
                return false;
            }

            if ("true".equals(status) || "expired".equals(status)) {
                return true;
            } else {
                return false;
            }
        });
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        LOGGER.info("getting user count ...");
        return doInLoggingProvider(session, ()-> {
            GetUsersCountResult result;
            try {
                result = nakisaService.getUsersCount();
            } catch (IOException | GeneralSecurityException exp) {
                LOGGER.error(MessageFormat.format("Error in user login in nakisa. {0}", getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("Error in user login in nakisa. {0}", getChainCauseMessage(exp)));
                return 0;
            }

            return Math.toIntExact(result.getUserCount());
        });
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) return false;
        UserCredentialModel cred = (UserCredentialModel) input;
        UserAdapter adapter = getUserAdapter(user);
        adapter.setPassword(cred.getValue());

        return true;
    }

    private UserAdapter getUserAdapter(UserModel user) {
        UserAdapter adapter = null;
        if (user instanceof CachedUserModel) {
            adapter = (UserAdapter) ((CachedUserModel) user).getDelegateForUpdate();
        } else {
            adapter = (UserAdapter) user;
        }
        return adapter;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) return;

        getUserAdapter(user).setPassword(null);
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        if (getUserAdapter(user).getPassword() != null) {
            Set<String> set = new HashSet<>();
            set.add(CredentialModel.PASSWORD);
            return set.stream();
        } else {
            return Stream.empty();
        }
    }

    @Override
    public void onCache(RealmModel realmModel, CachedUserModel cachedUserModel, UserModel userModel) {
        String password = ((UserAdapter) userModel).getPassword();
        if (password != null && !password.isBlank()) {
            cachedUserModel.getCachedWith().put(PASSWORD_CACHE_KEY, password);
        }
    }

    @Override
    public void close() {
        LOGGER.info("closing user storage provider");
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        return doInLoggingProvider(session, ()-> {
            LOGGER.info("getUserById: " + id);
            BigDecimal persistenceId;
            persistenceId = BigDecimal.valueOf(Long.parseLong(StorageId.externalId(id)));

            UserInfo entity;
            try {
                entity = (UserInfo) MyCache.extract("UserId=" + id, () -> nakisaService.getUserById(persistenceId));

                if (entity == null) {
                    LOGGER.info("could not find user by id: " + id);
                    return null;
                }
            } catch (Exception exp) {
                LOGGER.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", id, getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", id, getChainCauseMessage(exp)));
                return null;
            }
            if (entity == null) {
                LOGGER.info("could not find user by id: " + id);
                return null;
            }

            return new UserAdapter(session, realm, model, entity, nakisaService);
        });
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        return doInLoggingProvider(session, ()-> {
            LOGGER.info("getUserByUsername: " + username);

            UserInfo result;

            try {
                result = nakisaService.getUserByUsername(username);
                if (result == null) {
                    result = new UserInfo();
                    result.setCredentialsExpired(false);
                    result.setId(-1);
                    result.setMaxTryCount(-1);
                    result.setPasswordExpirationDate(new Date());
                    result.setUsername(username);
                }
            } catch (IOException | GeneralSecurityException exp) {
                LOGGER.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", username, getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", username, getChainCauseMessage(exp)));
                return null;
            }
            return new UserAdapter(session, realm, model, result, nakisaService);
        });
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        return null;
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
        LOGGER.info("search for user stream ....");
        return doInLoggingProvider(session, ()-> {
            GetSearchForUserResult result;
            try {
                result = nakisaService.searchForUserStream(params, firstResult, maxResults);
            } catch (IOException | GeneralSecurityException exp) {
                LOGGER.error(MessageFormat.format("Error in user login in nakisa. {0}", getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("Error in user login in nakisa. {0}", getChainCauseMessage(exp)));
                return null;
            }

            List<UserModel> users = new LinkedList<>();
            for (UserInfo entity : result.getUsers())
                users.add(new UserAdapter(session, realm, model, entity, nakisaService));
            return users.stream();
        });
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        LOGGER.info("getting group member stream stream ...");
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        LOGGER.info("searchForUserByUserAttributeStream ...");
        return Stream.empty();
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        return null;
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        return doInLoggingProvider(session, ()-> {
            String username = user.getUsername();
            BigDecimal persistenceId;
            persistenceId = BigDecimal.valueOf(Long.parseLong(StorageId.externalId(user.getId())));
            UserInfo entity;
            try {
                entity = nakisaService.getUserById(persistenceId);
                if (entity == null) {
                    LOGGER.info("could not find username: " + username);
                    return false;
                }
            } catch (IOException | GeneralSecurityException exp) {
                LOGGER.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", username, getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("Error in user login in nakisa. user:{0}, {1}", username, getChainCauseMessage(exp)));
                return false;
            }
            if (entity == null) return false;
            //em.remove(entity);
            return true;
        });
    }
}
