package com.modernisc.security.keycloak.iam.kc;

import com.modernisc.security.keycloak.iam.dto.*;
import com.modernisc.security.keycloak.iam.dto.mapper.UserMapper;
import com.modernisc.security.keycloak.iam.service.CustomService;
import com.modernisc.security.keycloak.iam.util.MyCache;
import jakarta.ejb.Local;
import jakarta.ejb.Stateful;
import org.jboss.logging.Logger;
import org.jboss.logging.MDC;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.*;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.storage.StorageId;

import org.keycloak.storage.UserStorageProvider;

import org.keycloak.storage.user.*;

import java.io.IOException;
import java.math.BigDecimal;
import java.security.*;
import java.text.MessageFormat;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static com.modernisc.security.keycloak.iam.util.ExceptionUtil.getChainCauseMessage;

@Stateful
@Local(CustomUserServiceProvider.class)
public class CustomUserServiceProvider implements
        UserStorageProvider,
        UserLookupProvider,
        UserQueryProvider,//UserQueryMethodsProvider,UserCountMethodsProvider
        CredentialInputValidator/*,
        OnUserCache*/
{


    private static final Logger LOGGER = Logger.getLogger(CustomUserServiceProvider.class);
    private static final Logger SECURITY_LOGGER = Logger.getLogger("com.modernisc.security.log");
    private CustomService customService;
    private String userName;
    protected ComponentModel model;
    protected KeycloakSession session;

    public CustomUserServiceProvider(KeycloakSession session, ComponentModel model,
                                     CustomService customService) {

        this.session = session;
        this.model = model;
        this.customService = customService;

        //this.userStorageManager = session.getProvider(UserStorageManager.class);


    }

    public ComponentModel getModel() {
        return model;
    }

    public void setModel(ComponentModel model) {
        this.model = model;
    }

    public void setSession(KeycloakSession session) {
        this.session = session;
    }

    private UserModel createUserAdapter(RealmModel realm, String username) {
        return createUserAdapter( realm, getCustomUserInfo(username));
    }
    private UserModel createUserAdapter(RealmModel realm, CustomUser userInfo) {
        //UserModel local = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(realm, userInfo.getUsername());
        UserModel local =  new CustomUserModel(this.session, realm, this.model,
                userInfo, customService);
        local.setFederationLink(model.getId());
        return new UserModelDelegate(local) {
            @Override
            public void setUsername(String username) {
                super.setUsername(username);
            }
        };
        /*UserCache cache = UserStorageUtil.userCache(session);
        UserModel local = cache.getUserByUsername(realm,userInfo.getUsername());
        if(local==null) {
            local = new customUserModel(session,realm, model,userInfo , customService);
            local.setFederationLink(model.getId());
        }
        return new UserModelDelegate(local) {
            @Override
            public void setUsername(String username) {
                super.setUsername(username);
            }
        };*/

    }

    private CustomUser getCustomUserInfo(String username) {

        CustomUser userInfo = new CustomUser();
        userInfo.setCredentialsExpired(false);
        userInfo.setId( -1 );
        userInfo.setMaxTryCount(-1);
        userInfo.setPasswordExpirationDate(new Date());
        userInfo.setUsername(username);
        userInfo.setCreatedTimeStamp(new Date());
        userInfo.setModifiedTimeStamp(new Date());
        userInfo.setEnabled(Boolean.TRUE.toString());


        return userInfo;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        return doInLoggingProvider(session, ()-> {
            String password = input.getChallengeResponse();
            GetAuthenticateScyUserResult result = null;
            try {
                result = customService.userLogin(user.getUsername(), password);
            } catch (Exception exp) {
                LOGGER.error(MessageFormat.format("custom>>Error in user login in custom. user:{0}, {1}", user.getUsername(), getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("custom>>Error in user login in custom. user:{0}, {1}", user.getUsername(), getChainCauseMessage(exp)));
                return false;
            }

            if (Boolean.valueOf(result.getAuthenticated())) {
                LOGGER.info(MessageFormat.format("User login suceeded. user:{0}", user.getUsername()));
                SECURITY_LOGGER.info(MessageFormat.format("User login suceeded. user:{0}", user.getUsername()));
                LOGGER.info("\r\r\n ----- isValid --- (true).equals(status) : return true ----- ");
                return true;
            } else {
                LOGGER.error(MessageFormat.format("User login failed. user:{0}", user.getUsername()));
                SECURITY_LOGGER.error(MessageFormat.format("User login failed. user:{0}", user.getUsername()));
                LOGGER.info("\r\r\n ----- isValid --- else : return false ----- ");
                return false;
            }
        });
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        LOGGER.info("\r\r\n ----- getUserById(String id, RealmModel realm) --- id: " + id + " ----- ");
        UserInfo userInfo = null;
        CustomUser customUser = null;
        StorageId storageId = new StorageId(id);
        String userId = storageId.getExternalId();
        try {
            if (!MyCache.exists(storageId.toString())) {
                LOGGER.info("\r\r\n ----- could not find user by id: " + id + " ----- ");
                userInfo = customService.getUserById(BigDecimal.valueOf(Long.parseLong(userId)));
                if (userInfo == null) {
                    LOGGER.info("\r\r\n ----- could not find user by id: " + id + " ----- ");
                    return null;
                }
                CustomUser finalCustomeUserInfo = UserMapper.toDto(userInfo);
                customUser = (CustomUser) MyCache.extract(storageId.toString(), () -> finalCustomeUserInfo);
            }else {
                customUser = (CustomUser) MyCache.extract(storageId.toString(), () -> getCustomUserInfo(this.userName));
                if(userInfo ==null || userInfo.getId()==-1){
                    MyCache.remove(storageId.toString());
                    userInfo = customService.getUserById(BigDecimal.valueOf(Long.parseLong(userId)));
                    if (userInfo == null) {
                        LOGGER.info("\r\r\n ----- could not find user by id: " + id + " ----- ");
                        return null;
                    }

                    CustomUser finalCustomUserInfo = UserMapper.toDto(userInfo);
                    customUser = (CustomUser) MyCache.extract(storageId.toString(), () -> finalCustomUserInfo);
                }
            }

        } catch (Exception exp) {
            LOGGER.error(MessageFormat.format("\r\r\n ----- Error in user login in nakisa. user:{0}, {1}", id, getChainCauseMessage(exp)));
            SECURITY_LOGGER.error(MessageFormat.format("\r\r\n ----- Error in user login in nakisa. user:{0}, {1}", id, getChainCauseMessage(exp)));
            return null;
        }

        return createUserAdapter(realm, customUser);
    }

    @Override
    public UserModel getUserByUsername( RealmModel realm,String username) {
        LOGGER.info("\r\r\n ----- getUserByUsername(String username, RealmModel realm) --- username: " + username + " ----- ");

        return doInLoggingProvider(session, () -> {
            UserInfo result;
            try {
                result = customService.getUserByUsername(username);
                if (result != null) {
                    UserModel userModel = createUserAdapter(realm, UserMapper.toDto(result));
                    MyCache.extract(StorageId.keycloakId(model, String.valueOf(result.getId())), () -> UserMapper.toDto(result));
                    //session.users().setNotBeforeForUser(realm, userModel, 0);
                    return userModel;
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
            return createUserAdapter(realm, username);
        });
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }
    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {

        return null;
    }
    /*@Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        if (email == null || email.isBlank()) return null;

        LOGGER.info("custom>>getUserByEmail email = " + email);

        try {
            Map<String,String> map = new HashMap<>();
            map.put("email",email);
            GetSearchForUserResult result = customService.searchForUserStream(map, 0 , 50);
            if (result == null || result.getUsers().size() == 0 )
                return null;

            return new CustomUserModel(session, realm, model,
                    result.getUsers().stream()
                    .findFirst().get(), customService);

        } catch (Exception e) {
            LOGGER.error("Error in getUserByEmail", e);
            return null;
        }

    }*/

    @Override
    public boolean supportsCredentialType(String credentialType) {
        System.out.println(" ----- supportsCredentialType ----- > > > " + credentialType);

        return PasswordCredentialModel.PASSWORD.equals(credentialType);
    }


    @Override
    public int getUsersCount(RealmModel realm) {
        return doInLoggingProvider(session, ()-> {
            GetUsersCountResult result;
            try {
                result = customService.getUsersCount();
            } catch (GeneralSecurityException| IOException  exp) {
                LOGGER.error(MessageFormat.format("custom>>Error in user login in custom. {0}", getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("custom>>Error in user login in custom. {0}", getChainCauseMessage(exp)));
                return 0;
            }

            return Math.toIntExact(result.getUserCount());
        });
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
        LOGGER.info("custom>>call search for user stream method ....");
        return doInLoggingProvider(session, ()-> {
            GetSearchForUserResult result;
            try {
                result = customService.searchForUserStream(params, firstResult, maxResults);
            } catch (IOException | GeneralSecurityException exp) {
                LOGGER.error(MessageFormat.format("custom>>Error in user login in nakisa. {0}", getChainCauseMessage(exp)));
                SECURITY_LOGGER.error(MessageFormat.format("custom>>Error in user login in custom. {0}", getChainCauseMessage(exp)));
                return null;
            }

            List<UserModel> users = new LinkedList<>();
            for (UserInfo entity : result.getUsers())
                users.add(new CustomUserModel(session, realm, model,UserMapper.toDto(entity), customService));
            return users.stream();
        });
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realmModel, GroupModel groupModel, Integer integer, Integer integer1) {
        return Stream.empty();
    }
/*    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realmModel, String s, String s1) {
        return Stream.empty();
    }*/
    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realmModel, String attrName, String attrValue) {
        LOGGER.info("custom>>searchForUserByUserAttributeStream attr=" + attrName + " value=" + attrValue);

        if (attrValue == null || attrValue.isBlank()) return Stream.empty();

        // ۱) اگر ایمیل یا یوزرنیم بود → از متدهای خودم استفاده کنم
        if ("email".equalsIgnoreCase(attrName)) {
            UserModel u = getUserByEmail(realmModel, attrValue);
            return u == null ? Stream.empty() : Stream.of(u);
        }
        if ("username".equalsIgnoreCase(attrName)) {
            UserModel u = getUserByUsername(realmModel, attrValue);
            return u == null ? Stream.empty() : Stream.of(u);
        }

        try {
            HashMap<String,String> map = new HashMap<>();
            map.put(attrName,attrValue);
            GetSearchForUserResult result = customService.searchForUserStream(map, 0 , 50);
            if (result == null || result.getUsers()==null ||
                    result.getUsers().size() == 0 )

                return Stream.empty();

            return result.getUsers().stream()
                    .map(ui -> new CustomUserModel(session, realmModel, model,
                            UserMapper.toDto(ui), customService));
        } catch (Exception e) {
            LOGGER.error("Error in searchForUserByUserAttributeStream", e);
            return Stream.empty();
        }
    }

    private <T> T doInLoggingProvider(KeycloakSession session, Supplier<T> method) {

        LOGGER.info("----- doInLoggingProvider(KeycloakSession session, Supplier<T> method) --- ip: "
                + session.getContext().getConnection().getRemoteAddr() + " ----- ");

        MDC.put("ip --- ", session.getContext().getConnection().getRemoteAddr());

        try {
            return method.get();
        } finally {
            MDC.remove("ip");
        }
    }

    @Override
    public void close() {
    }

    public static final String EMAIL_CACHE_KEY = CustomUserModel.class.getName() + ".email";

   /* @Override
    public void onCache(RealmModel realmModel, CachedUserModel cachedUserModel, UserModel delegate) {

        System.out.println(" ----- onCache ----- > > > " + cachedUserModel.toString());
        String email = ((CustomUserModel) delegate).getUserByEmail(cachedUserModel);
        if (email != null) {
            cachedUserModel.getCachedWith().put(EMAIL_CACHE_KEY, email);
        }
    }*/

    public String getUserByEmail(UserModel user) {

        String email = null;
        if (user instanceof CachedUserModel) {
            LOGGER.info("\r\r\n ----- getUserByEmail >>> user instanceof CachedUserModel ");
            email = (String) ((CachedUserModel) user).getCachedWith().get(EMAIL_CACHE_KEY);
        } else if (user instanceof CustomUserModel) {
            LOGGER.info("\r\r\n ----- getUserByEmail >>> user instanceof UserAdapter ");
            email = ((CustomUserModel) user).getUserByEmail(user);
        }

        LOGGER.info("\r\r\n ----- getUserByEmail >>> userName is : " + email + " ----- ");
        return email;
    }

}
