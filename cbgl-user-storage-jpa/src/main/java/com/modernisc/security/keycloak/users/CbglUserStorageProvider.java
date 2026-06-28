package com.modernisc.security.keycloak.users;

import com.modernisc.security.keycloak.users.dto.UserDto;
import io.agroal.api.AgroalDataSource;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserCountMethodsProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryMethodsProvider;
import org.keycloak.storage.user.UserQueryProvider;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Stream;

public class CbglUserStorageProvider
        implements UserStorageProvider,
        UserLookupProvider,
        UserQueryProvider,
        UserQueryMethodsProvider,
        UserCountMethodsProvider,
        CredentialInputValidator//,
//        OnUserCache
{

    private static final Logger logger = Logger.getLogger(CbglUserStorageProvider.class);

    private AgroalDataSource dataSource;
    protected ComponentModel model;
    protected KeycloakSession session;

    public CbglUserStorageProvider(
            KeycloakSession session,
            ComponentModel model,
            AgroalDataSource dataSource) {

        this.session = session;
        this.model = model;
        this.dataSource = dataSource;

    }

    private Connection getConnection() throws SQLException {
        return dataSource.getConnection(); // هر بار اتصال جدید
    }

    public void setModel(ComponentModel model) {
        this.model = model;
    }

    public void setSession(KeycloakSession session) {
        this.session = session;
    }

    private UserModel createUserAdapter(RealmModel realm, String username) {
        return createUserAdapter(realm, getUserInfo(username));
    }

    /*private UserModel createUserAdapter(RealmModel realm, UserDto userInfo) {
        //UserModel local = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(realm, userInfo.getUsername());
        UserModel local = new UserAdapter(this.session, realm, this.model, userInfo, this);
        local.setFederationLink(model.getId());
        return new UserModelDelegate(local) {
            @Override
            public void setUsername(String username) {
                super.setUsername(username);
            }
        };
    }*/
// ==================== USER ADAPTER ====================

    private UserModel createUserAdapter(RealmModel realm, UserDto userDto) {
        // Load roles from custom database
        userDto.setRoles(getRolesByUserId(userDto.getId()));

        return new UserAdapter(session, realm, model, userDto, this);
    }

    private UserDto getUserInfo(String username) {
        UserDto user = getUserByUsername(username);
        if (user == null) {
            UserDto userInfo = new UserDto();
            userInfo.setId(-1L);
            userInfo.setDescription("test");
            userInfo.setPassword("test");
            userInfo.setUsername(username);
            userInfo.setFirstName("test");
            userInfo.setPasswordExpirationDate(LocalDateTime.MAX);
            userInfo.setRoles((Set<Role>) new ArrayList());
            userInfo.setEnabled("true");
            userInfo.setEmployeeNumber("1111111");
            userInfo.setCreatedTimeStamp(LocalDateTime.now());
            userInfo.setEmail("info@h.com");
            userInfo.setTemporary("false");
            return userInfo;
        }
        return user;
    }

    public UserDto getUserByUsername(String username) {
        if (username == null)
            return null;
        if ("service-account-cbgl-service".equals(username)) {
            logger.warnf("=== Service account login detected ===");
        }
        String sql = username.matches("\\d+")
                ? "SELECT * FROM cbgl_user WHERE employee_number = ?"
                : "SELECT * FROM cbgl_user WHERE username = ?";

        UserDto userDto = null;
        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setQueryTimeout(60); // ✅ 60 ثانیه برای اجرای query
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next())
                    return null;
                userDto = mapRow(rs);

            }
        } catch (SQLException e) {
            logger.error("JDBC error in getUserByUsername for: " + username, e);
            return null;
        }
        if (userDto != null) {
            userDto.setRoles(getRolesByUserId(userDto.getId()));// تبدیل ResultSet به Entity شما
        }
        return userDto;
    }

    @Override
    public void close() {
//        em.close();
    }

    UserDto userDto = null;

    public UserDto getUserById(Long id) {
        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(
                     "select ID, CREATED_ON,DESCRIPTION ,EMAIL,EMPLOYEE_NUMBER, ENABLE ,FIRST_NAME    ," +
                             "IS_TEMPORARY ,IS_TEMPORARY , LAST_NAME, PASSWORD , PASSWORD_EXPIRY_DATE,USERNAME " +
                             "FROM CBGL_USER WHERE ID = ?")) {
            ps.setQueryTimeout(60); // ✅ 60 ثانیه برای اجرای query
            ps.setString(1, String.valueOf(id));
            ResultSet rs = ps.executeQuery();
            if (!rs.next())
                return null;
            userDto = mapRow(rs);

        } catch (SQLException e) {
            e.printStackTrace();
            logger.error("could not find user by id: " + id, e);
            throw new RuntimeException(e);
        }
        if (userDto != null)
            userDto.setRoles(getRolesByUserId(userDto.getId()));// تبدیل ResultSet به Entity شما
        return userDto;
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        String persistenceId = StorageId.externalId(id);
        UserDto entity = getUserById(Long.valueOf(persistenceId));

        if (entity == null) {
            logger.info("could not find user by id: " + id);
            return null;
        }

        return new UserAdapter(session, realm, model, entity, this);
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        if (username == null) return null;

        String sql = username.matches("\\d+")
                ? "SELECT * FROM cbgl_user WHERE employee_number = ?"
                : "SELECT * FROM cbgl_user WHERE username = ?";
        UserDto userDto = null;
        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setQueryTimeout(60); // ✅ 60 ثانیه برای اجرای query
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next())
                    return null;

                userDto = mapRow(rs);

            }
        } catch (SQLException e) {
            logger.error("JDBC lookup error for username " + username, e);
            return null;
        }
        if (userDto != null) {
            userDto.setRoles(getRolesByUserId(userDto.getId()));// تبدیل ResultSet به Entity شما
            return new UserAdapter(session, realm, model, userDto, this);
        }
        logger.error("user not found");
        return null;
    }

    private UserDto mapRow(ResultSet rs) throws SQLException {
        UserDto u = new UserDto();
        u.setId(rs.getLong("ID"));
        logger.debug("=== Mapped user ID: " + u.getId() + " from DB"); // دیباگ
        u.setUsername(rs.getString("USERNAME"));        // اجباری در DB پس null نمی‌آید
        u.setPassword(rs.getString("PASSWORD"));        // اجباری
        u.setFirstName(getNullableString(rs, "FIRST_NAME"));
        u.setLastName(getNullableString(rs, "LAST_NAME"));
        u.setEmail(getNullableString(rs, "EMAIL"));
        u.setEmployeeNumber(getNullableString(rs, "EMPLOYEE_NUMBER"));
        u.setDescription(getNullableString(rs, "DESCRIPTION"));

        // Boolean – getBoolean اگر NULL بود false برمی‌گرداند → چک کنید
        u.setEnabled(String.valueOf(getNullableBoolean(rs, "ENABLE")));
        u.setTemporary(String.valueOf(getNullableBoolean(rs, "IS_TEMPORARY")));

        // LocalDateTime
        Timestamp ts = rs.getTimestamp("PASSWORD_EXPIRY_DATE");
        u.setPasswordExpirationDate(ts == null ? LocalDateTime.MAX : ts.toLocalDateTime());

        ts = rs.getTimestamp("CREATED_ON");
        u.setCreatedTimeStamp(ts == null ? LocalDateTime.now() : ts.toLocalDateTime());
        return u;
    }

    private String getNullableString(ResultSet rs, String column) throws SQLException {
        String val = rs.getString(column);
        return val == null ? "" : val;
    }

    private boolean getNullableBoolean(ResultSet rs, String column) throws SQLException {
        boolean b = rs.getBoolean(column);
        return !rs.wasNull() && b;
    }

    /*@Override
    public UserModel addUser(String username, RealmModel realm) {
        User entity = new User();
        entity.setUsername(username);
        entity.setEnable(true);
        em.persist(entity);
        logger.info("added user: " + username);

        return new UserAdapter(session, realm, model, entity);
    }

    @Override
    public boolean removeUser( UserModel user, RealmModel realm) {
        String persistenceId = StorageId.externalId(user.getId());
        User entity = em.find(User.class, persistenceId);

        if (entity == null) {
            return false;
        }

        em.remove(entity);

        return true;
    }
*/
    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        if (email == null)
            return null;
        String sql = "SELECT * FROM CBGL_USER WHERE email = ?";
        UserDto userDto1 = null;
        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setQueryTimeout(60); // ✅ 60 ثانیه برای اجرای query
            ps.setString(1, email);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                userDto1 = mapRow(rs);

            }
        } catch (SQLException e) {
            logger.error("JDBC lookup error for email " + email, e);
            return null;
        }
        if (userDto1 != null) {
            userDto1.setRoles(getRolesByUserId(userDto1.getId()));
            return new UserAdapter(session, realm, model, userDto1, this);
        }

        return null;
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        logger.info("getUsersCount cbgl ...");
        String sql = "SELECT COUNT(*) FROM CBGL_USER";

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setQueryTimeout(60);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                return rs.getInt(1);
            }
            return 0;
        } catch (SQLException e) {
            logger.error("getUsersCount JDBC error", e);
            return 0;   // در صورت خطا ۰ برگردانید تا Keycloak crash نکند
        }
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return CredentialModel.PASSWORD.equals(credentialType);
    }


    public boolean updateCredential(
            RealmModel realm,
            UserModel user,
            CredentialInput input) {

        if (!supportsCredentialType(input.getType()) ||
                !(input instanceof UserCredentialModel)) {
            return false;
        }

        UserCredentialModel cred = (UserCredentialModel) input;
        UserAdapter adapter = getUserAdapter(user);
        String rawId = user.getId();
        int idx = rawId.lastIndexOf(':');

        String suffix = rawId.substring(idx + 1);
        adapter.setPassword(encode(cred.getValue(), suffix.getBytes()));
        adapter.setTemporary(false);
        return true;
    }

    public UserAdapter getUserAdapter(UserModel user) {
        if (user instanceof CachedUserModel) {
            return (UserAdapter) ((CachedUserModel) user).getDelegateForUpdate();
        } else {
            return (UserAdapter) user;
        }
    }


    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) return false;

        String password = input.getChallengeResponse();
        String sql = "SELECT PASSWORD, PASSWORD_EXPIRY_DATE FROM CBGL_USER WHERE USERNAME = ?";

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setQueryTimeout(60); // ✅ 60 ثانیه برای اجرای
            ps.setString(1, user.getUsername());
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    logger.error("user not found. user: " + user.getUsername());
                    return false;                     // کاربر یافت نشد
                }
                String dbHash = rs.getString("PASSWORD");
                Timestamp expiryTs = rs.getTimestamp("PASSWORD_EXPIRY_DATE");
                LocalDateTime expiryDate = expiryTs == null ? LocalDateTime.MAX :
                        expiryTs.toLocalDateTime();


                /* ساختن همان suffix = externalId پس‌از ":" */
                String rawId = user.getId();
                int idx = rawId.lastIndexOf(':');
                String suffix = rawId.substring(idx + 1);

                boolean match = matches(password, dbHash, suffix.getBytes());
                if (!match) {
                    logger.error("Invalid password for user " + user.getUsername());
                    return false;
                }

                if (expiryDate != null && expiryDate.isBefore(LocalDateTime.now())) {
                    UserAdapter adapter = getUserAdapter(user);
                    adapter.setTemporary(true);
                }
                return true;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            logger.error("JDBC error during password validation for " + user.getUsername(), e);
            return false;
        }
    }

    public String encode(String toBeEncoded, byte[] salt) {

        PBEKeySpec spec = new PBEKeySpec(toBeEncoded.toCharArray(), salt, 100, 64 * 8);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            return Base64.getEncoder().encodeToString(skf.generateSecret(spec).getEncoded());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error("encode cbgl error.", e);
            throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
        } finally {
            spec.clearPassword();
        }

    }

    public boolean matches(String raw, String expectedHash, byte[] salt) {
        String pwdHash = encode(raw, salt);
        if (pwdHash.getBytes().length != expectedHash.getBytes().length) return false;
        return Arrays.equals(pwdHash.getBytes(), expectedHash.getBytes());
    }


    public List<UserModel> getUsers(RealmModel realmModel) {
        return getUsers(realmModel, 0, Integer.MAX_VALUE);
    }


    public List<UserModel> getUsers(RealmModel realmModel, int firstResult, int maxResults) {
        logger.info("getUsers cbgl ...");
        String sql = "SELECT * FROM CBGL_USER ORDER BY USERNAME OFFSET ? ROWS FETCH NEXT ? ROWS ONLY"; // Oracle 12c+
        List<UserModel> users = new LinkedList<>();
        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setQueryTimeout(60); // ✅ 60 ثانیه برای اجرای
            ps.setInt(1, firstResult);
            ps.setInt(2, maxResults);

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    try {
                        UserDto u = mapRow(rs);
                        UserAdapter adapter = new UserAdapter(session, realmModel, model, u, this);
                        users.add(adapter);
                    } catch (Exception exception) {
                        logger.error("getUsers error", exception);
                        exception.printStackTrace();
                    }
                }

            }
        } catch (SQLException e) {
            logger.error("getUsers error", e);
            return Collections.emptyList();
        }
        for (UserModel u : users) {
            ((UserAdapter) u).getUser().setRoles(getRolesByUserId(((UserAdapter) u).getUser().getId()));
        }
        return users;
    }

    public Set<Role> getRolesByUserId(Long userId) {
        logger.info("getRolesByUserId cbgl ...");
        String sql = """
                SELECT R.ID, R.NAME
                FROM CBGL_ROLE R
                JOIN CBGL_USER_ROLE UR ON R.ID = UR.ROLE_ID
                WHERE UR.USER_ID = ?
                """;
        Set<Role> roles = new LinkedHashSet<>();
        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setQueryTimeout(60); // ✅ 60 ثانیه برای اجرای
            ps.setLong(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Role r = new Role();
                    r.setId(rs.getLong("id"));
                    r.setName(rs.getString("name"));
                    roles.add(r);
                }

            }
        } catch (SQLException e) {
            logger.error("getUsers JDBC error", e);
            throw new RuntimeException("Failed to load roles for user " + userId, e);
        }
        logger.info("getRolesByUserId cbgl called. count = " + roles.stream().count());
        return roles;
    }

    public List<UserModel> searchForUser(String search,
                                         RealmModel realmModel,
                                         int firstResult,
                                         int maxResults) {
        logger.info("searchForUser cbgl ...");
        // اگر جستجو خالی بود → همه کاربران
        if (search == null || search.isEmpty()) {
            return getUsers(realmModel, firstResult, maxResults);
        }

        String pattern = "%" + search.toLowerCase().replace("*", "%") + "%";
        String sql = """
                SELECT * FROM CBGL_USER
                WHERE ( LOWER(username) LIKE ? OR LOWER(email) LIKE ? )
                ORDER BY username
                OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
                """;   // Oracle 12c+ syntax
        List<UserModel> users = new ArrayList<>();
        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setQueryTimeout(60); // ✅ 60 ثانیه برای اجرای
            ps.setString(1, pattern);
            ps.setString(2, pattern);
            ps.setInt(3, firstResult);
            ps.setInt(4, maxResults);

            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    UserDto u = mapRow(rs);
                    UserAdapter adapter = new UserAdapter(session, realmModel, model, u, this);
                    users.add(adapter);
                }

            }
        } catch (SQLException e) {
            logger.error("searchForUser JDBC error", e);
            return Collections.emptyList();
        }
        for (UserModel u : users) {
            ((UserAdapter) u).getUser().setRoles(getRolesByUserId(((UserAdapter) u).getUser().getId()));
        }
        return users;
    }

    public List<UserModel> searchForUser(RealmModel realmModel, Map<String, String> params) {
        return searchForUser(params, realmModel, 0, Integer.MAX_VALUE);
    }


    public List<UserModel> searchForUser(Map<String, String> params,
                                         RealmModel realmModel,
                                         int firstResult,
                                         int maxResults) {
        if (params.containsKey("email")) {
            UserModel u = getUserByEmail(realmModel, params.get("email"));
            return u != null ? List.of(u) : List.of();
        }
        if (params.containsKey("username")) {
            UserModel u = getUserByUsername(realmModel, params.get("username"));
            return u != null ? List.of(u) : List.of();
        }
        // fallback to generic search
        return searchForUser((String) null, realmModel, firstResult, maxResults);
    }


    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realmModel, Map<String, String> params,
                                                 Integer firstResult, Integer maxResults) {
        try {
            return searchForUser(params, realmModel, firstResult, maxResults).stream();
        } catch (Exception e) {
            logger.error("searchForUserStream error", e);
            return Stream.empty();
        }
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realmModel, GroupModel groupModel, Integer integer, Integer integer1) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realmModel, String attrName, String attrValue) {
        logger.info("searchForUserByUserAttributeStream attr=" + attrName + " value=" + attrValue);

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

        // ۲) برای بقیه attribute‌ها (مثلاً employeeNumber) → JDBC
        String sql = "SELECT * FROM CBGL_USER WHERE " + attrName + " = ?";
        List<UserModel> users = new ArrayList<>();
        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setQueryTimeout(60); // ✅ 60 ثانیه برای اجرای
            ps.setString(1, attrValue);
            try (ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    UserDto u = mapRow(rs);

                    users.add(new UserAdapter(session, realmModel, model, u, this));
                }

            }
        } catch (SQLException e) {
            logger.error("searchByAttribute JDBC error", e);
            return Stream.empty();
        }
        for (UserModel u : users) {
            ((UserAdapter) u).getUser().setRoles(getRolesByUserId(((UserAdapter) u).getUser().getId()));
        }
        return users.stream();
    }

    /**
     * انتساب role به کاربر در دیتابیس سفارشی
     */
    public boolean assignRoleToUser(Long userId, Long roleId) {
        logger.debugv("Assigning role {0} to user {1}", roleId, userId);

        String sql = "INSERT INTO CBGL_USER_ROLE (USER_ID, ROLE_ID) VALUES (?, ?)";

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setLong(1, userId);
            ps.setLong(2, roleId);

            int inserted = ps.executeUpdate();

            if (inserted > 0) {
                logger.infov("ROLE_ASSIGNED | UserId: {0} | RoleId: {1}", userId, roleId);
                return true;
            }

        } catch (SQLIntegrityConstraintViolationException e) {
            logger.warnv("Role {0} already assigned to user {1}", roleId, userId);
            return false; // Already exists

        } catch (SQLException e) {
            logger.errorv(e, "Failed to assign role {0} to user {1}", roleId, userId);
            throw new RuntimeException("Failed to assign role", e);
        }

        return false;
    }
    /**
     * حذف انتساب role از کاربر در دیتابیس سفارشی
     */
    public boolean unassignRoleFromUser(Long userId, Long roleId) {
        logger.debugv("Unassigning role {0} from user {1}", roleId, userId);

        String sql = "DELETE FROM CBGL_USER_ROLE WHERE USER_ID = ? AND ROLE_ID = ?";

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setLong(1, userId);
            ps.setLong(2, roleId);

            int deleted = ps.executeUpdate();

            if (deleted > 0) {
                logger.infov("ROLE_UNASSIGNED | UserId: {0} | RoleId: {1}", userId, roleId);
                return true;
            } else {
                logger.warnv("Role assignment not found | User: {0} | Role: {1}", userId, roleId);
                return false;
            }

        } catch (SQLException e) {
            logger.errorv(e, "Failed to unassign role {0} from user {1}", roleId, userId);
            throw new RuntimeException("Failed to unassign role", e);
        }
    }
    /**
     * یافتن role ID بر اساس نام
     */
    public Long findRoleIdByName(String roleName) {
        String sql = "SELECT ID FROM CBGL_ROLE WHERE NAME = ?";

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setString(1, roleName);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong("ID");
                }
            }
        } catch (SQLException e) {
            logger.errorv(e, "Failed to find role by name: {0}", roleName);
        }

        return null;
    }
}
