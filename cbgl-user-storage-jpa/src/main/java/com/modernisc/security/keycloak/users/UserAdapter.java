package com.modernisc.security.keycloak.users;


import com.modernisc.security.keycloak.users.dto.UserDto;
import org.jboss.logging.Logger;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;
import org.keycloak.models.UserModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.federated.UserFederatedStorageProvider;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.MessageFormat;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Stream;

import static com.modernisc.security.keycloak.users.util.ExceptionUtil.getChainCauseMessage;
import static org.keycloak.services.ServicesLogger.LOGGER;

public class UserAdapter extends AbstractUserAdapterFederatedStorage
        implements UserModel {

    private static final Logger logger = Logger.getLogger(UserAdapter.class);
    private final UserDto entity;
    private final String keycloakId;
    private final CbglUserStorageProvider provider;

    public UserDto getUser() {
        return entity;
    }



    public UserAdapter(KeycloakSession session, RealmModel realm, ComponentModel model,
                       UserDto userDto, CbglUserStorageProvider cbglUserStorageProvider) {
        super(session, realm, model);
        this.entity = userDto;
        setCreatedTimestamp(new Date().getTime());
        if (model == null) {
            logger.error("=== FATAL: ComponentModel is NULL ===");
        }
        if (userDto == null) {
            logger.error("=== FATAL: User entity is NULL ===");
        }
        keycloakId = StorageId.keycloakId(model, String.valueOf(userDto.getId()));

        provider = cbglUserStorageProvider;

        logger.debug("=== Generated keycloakId: " + keycloakId + " for user: " + userDto.getUsername());


    }

    @Override
    public String getId() {
        return keycloakId;
    }

    @Override
    public String getUsername() {
        return entity.getUsername();
    }

    @Override
    public void setUsername(String username) {

        throw new UnsupportedOperationException("Read-only user");
    }
    // ==================== ROLE MANAGEMENT ====================

    /**
     * دریافت همه roleهای کاربر (از دیتابیس سفارشی + realm defaults)
     */
    @Override
    public Stream<RoleModel> getRoleMappingsStream() {
        // ۱. Roleهای از دیتابیس سفارشی
        Stream<RoleModel> customRoles = entity.getRoles() != null ?
                entity.getRoles().stream()
                        .map(this::toRoleModel) :
                Stream.empty();

        // ۲. Realm Roles از Keycloak (از USER_ROLE_MAPPING table)
        Stream<RoleModel> realmRoles = getRealmRoles();

        // ۳. Realm Default Roles (اختیاری)
        //Stream<RoleModel> defaultRoles = getDefaultRoles();

        return Stream.of(customRoles, realmRoles)
                .flatMap(s -> s)
                .distinct();
    }
    private Stream<RoleModel> getRealmRoles() {
        // از FederatedStorage provider برای خواندن از USER_ROLE_MAPPING
        return session.getProvider(UserFederatedStorageProvider.class)
                .getRoleMappingsStream(realm, getId());
    }
    /**
     * Realm Default Roles
     */
    private Stream<RoleModel> getDefaultRoles() {
        if (!appendDefaultRolesToRoleMappings()) {
            return Stream.empty();
        }

        RoleModel defaultRole = realm.getDefaultRole();
        if (defaultRole == null) {
            return Stream.empty();
        }

        return defaultRole.getCompositesStream();
    }
    /**
     * تبدیل Role entity به RoleModel
     */
    private RoleModel toRoleModel(Role role) {
        return new CbglRole(
                String.valueOf(role.getName()),  // ID as String
                "CBGL Role: " + role.getName(),
                Long.toString(role.getId()),
                this.realm,
                false  // Not a client role
        );
    }

    /**
     * بررسی آیا کاربر role را دارد
     */
    @Override
    public boolean hasRole(RoleModel role) {
        // Check in custom roles
        boolean hasCustomRole = entity.getRoles() != null &&
                entity.getRoles().stream()
                        .anyMatch(r -> r.getName().equals(role.getName()) ||
                                String.valueOf(r.getId()).equals(role.getId()));

        if (hasCustomRole) {
            logger.debugv("User {0} has custom role {1}", getUsername(), role.getName());
            return true;
        }

        // Check realm default roles
        boolean hasDefaultRole = RoleUtils.hasRoleFromGroup(
                this.getGroupsStream(), role, true);

        return hasDefaultRole;
    }

    /**
     * انتساب role به کاربر
     */
    @Override
    public void grantRole(RoleModel role) {
        logger.debugv("grantRole called | User: {0} | Role: {1} (ID: {2})",
                getUsername(), role.getName(), role.getId());

        // بررسی آیا قبلاً دارد
        if (hasRole(role)) {
            logger.warnv("User {0} already has role {1}", getUsername(), role.getName());
            return;
        }

        // یافتن role ID در دیتابیس سفارشی
        Long roleId = findCustomRoleId(role);
        if (roleId == null) {
            logger.errorv("Role {0} not found in custom database", role.getName());
            throw new RuntimeException("Role not found: " + role.getName());
        }

        // انتساب در دیتابیس سفارشی
        boolean success = provider.assignRoleToUser(entity.getId(), roleId);

        if (success) {
            // به‌روزرسانی cache محلی
            Role newRole = new Role();
            newRole.setId(roleId);
            newRole.setName(role.getName());
            entity.getRoles().add(newRole);

            logger.infov("Role granted successfully | User: {0} | Role: {1}",
                    getUsername(), role.getName());
        }
    }

    /**
     * حذف انتساب role از کاربر
     */
    @Override
    public void deleteRoleMapping(RoleModel role) {
        logger.debugv("deleteRoleMapping called | User: {0} | Role: {1}",
                getUsername(), role.getName());

        // یافتن role ID
        Long roleId = findCustomRoleId(role);
        if (roleId == null) {
            logger.warnv("Role {0} not found in custom database", role.getName());
            if (realm.getRole(role.getName()) == null) {
                logger.warnf("Realm role '%s' not found – cannot grant to user '%s'", role.getName(), getUsername());
                return;
            }
            this.getFederatedStorage().deleteRoleMapping(this.realm, this.getId(), role);
            return;
        }

        // حذف انتساب از دیتابیس سفارشی
        boolean success = provider.unassignRoleFromUser(entity.getId(), roleId);

        if (success) {
            // به‌روزرسانی cache محلی
            entity.getRoles().removeIf(r -> r.getId().equals(roleId));

            logger.infov("Role unassigned successfully | User: {0} | Role: {1}",
                    getUsername(), role.getName());
        }
    }

    /**
     * یافتن ID role در دیتابیس سفارشی
     */
    private Long findCustomRoleId(RoleModel role) {
        // اگر ID عددی است (از دیتابیس سفارشی)
        try {
            return Long.parseLong(role.getId());
        } catch (NumberFormatException e) {
            // جستجو بر اساس نام
            return provider.findRoleIdByName(role.getName());
        }
    }

    @Override
    public Long getCreatedTimestamp() {

        return new Date().getTime();
    }

    @Override
    public void setCreatedTimestamp(Long aLong) {

    }

    @Override
    public String getEmail() {
        return entity.getEmail();
    }


    @Override
    public String getFirstName() {
        return entity.getFirstName();
    }

    @Override
    public String getLastName() {
        return entity.getLastName();
    }

    @Override
    public boolean isEnabled() {

        boolean enabled = entity != null && Boolean.parseBoolean(entity.getEnabled());
        logger.debug("=== isEnabled() for " + (entity != null ? entity.getUsername() : "null") + " = " + enabled);
        return enabled;
    }

    public String getPasswordHash() {
        return entity.getPassword();
    }

    public void setPassword(String password_hash) {
        entity.setPassword(password_hash);
    }

    @Override
    protected Set<RoleModel> getRoleMappingsInternal() {
        Set<RoleModel> roleModels = new HashSet<>();
        Set<Role> userRoles = entity.getRoles();
        if (userRoles != null) {
            for (Role role : userRoles) {
                roleModels.add(new CbglRole(role.getName(),
                        "cbgl-role", UUID.randomUUID().toString(), this.realm,false));
            }
        }
        return roleModels;
    }

    public boolean isTemporary() {
        return Boolean.parseBoolean(entity.getTemporary());
    }

    public void setTemporary(boolean temporary) {
        entity.setTemporary(Boolean.toString(temporary));
    }

    @Override
    public String getServiceAccountClientLink() {
        if (super.getServiceAccountClientLink() != null)
            return super.getServiceAccountClientLink();
        return serviceAccountClientLink;
    }

    String serviceAccountClientLink;

    @Override
    public void setServiceAccountClientLink(String s) {
        serviceAccountClientLink = s;
    }

    public Set<Role> getUserRoleSet(long userId) {
        Set<Role> result;
        try {
            result = entity.getRoles();
        } catch (Exception exp) {
            logger.error(MessageFormat.format("Error in user login in cbgl. {0}", getChainCauseMessage(exp)));
//            SECURITY_LOGGER.error(MessageFormat.format("Error in user login in nakisa. {0}", getChainCauseMessage(exp)));
            return null;
        }
        if (result == null)
            return Collections.EMPTY_SET;
        return result;
    }

/*
    @Override
    public boolean isValid(List<CredentialInput> inputs) {
        for (CredentialInput input : inputs) {
            if (!isValidCredential(input)) {
                return false;
            }
        }
        return true;
    }*/

    private boolean isValidCredential(CredentialInput input) {
        if (input.getType().equals(CredentialModel.PASSWORD)) {
            return entity.getPassword() != null &&
                    entity.getPassword().equals(input.getChallengeResponse());
        }
        return false; // یا delegate به credential provider
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
/*
    @Override
    public boolean updateCredential(CredentialInput credentialInput) {
        if (isValidCredential(credentialInput) ||
                !(credentialInput instanceof UserCredentialModel)) {
            return false;
        }

        UserCredentialModel cred = (UserCredentialModel) credentialInput;
        UserAdapter adapter = this;
        String rawId = String.valueOf(entity.getId());
        int idx = rawId.lastIndexOf(':');

        String suffix = rawId.substring(idx + 1);
        adapter.setPassword(encode(cred.getValue(), suffix.getBytes()));
        adapter.setTemporary(false);
        return true;
    }*/

   /* @Override
    public void updateStoredCredential(CredentialModel credentialModel) {

    }

    @Override
    public CredentialModel createStoredCredential(CredentialModel credentialModel) {
        return credentialModel;
    }

    @Override
    public boolean removeStoredCredentialById(String s) {
        return false;
    }

    @Override
    public CredentialModel getStoredCredentialById(String s) {
        return null;
    }

    @Override
    public Stream<CredentialModel> getStoredCredentialsStream() {
        return Stream.empty();
    }

    //لیست انواع credentialهایی را برمی‌گرداند که می‌توانند
    // برای یک کاربر غیرفعال شوند بدون اینکه حذف شوند
    @Override
    public Stream<CredentialModel> getStoredCredentialsByTypeStream(String s) {
        return Stream.empty();
    }


    @Override
    public CredentialModel getStoredCredentialByNameAndType(String name, String type) {
        return null;
    }

    @Override
    public boolean moveStoredCredentialTo(String s, String s1) {
        return false;
    }

    @Override
    public void updateCredentialLabel(String s, String s1) {

    }

    @Override
    public void disableCredentialType(String s) {

    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream() {
        return Stream.empty();
    }

    @Override
    public boolean isConfiguredFor(String s) {
        return false;
    }

    @Override
    public boolean isConfiguredLocally(String s) {
        return false;
    }

    @Override
    public Stream<String> getConfiguredUserStorageCredentialTypesStream() {
        return Stream.empty();
    }

    @Override
    public CredentialModel createCredentialThroughProvider(CredentialModel credentialModel) {
        return credentialModel;
    }
*/
    @Override
    public boolean isEmailVerified() {
        return true;
    }

    public List<String> getAttribute(String name) {
        return getAttributes().getOrDefault(name, List.of());
    }

    @Override
    public String getFirstAttribute(String name) {
        List<String> values = getAttribute(name);
        return values.isEmpty() ? null : values.get(0);
    }

    @Override
    public Stream<String> getRequiredActionsStream() {
        logger.warn("=== Skipping required actions for: " + entity.getUsername());
        List<String> actions = new ArrayList<>();

        // اگر کاربر موقت است، حتماً باید پسورد عوض کند
        if (Boolean.parseBoolean(entity.getTemporary())) {
            actions.add(UserModel.RequiredAction.UPDATE_PASSWORD.name());
        }

        // اگر پسورد منقضی شده
        if (entity.getPasswordExpirationDate() != null &&
                !entity.getPasswordExpirationDate().equals(LocalDateTime.MAX) &&
                entity.getPasswordExpirationDate().isBefore(LocalDateTime.now())) {
            actions.add(UserModel.RequiredAction.UPDATE_PASSWORD.name());
        }

        // دیباگ لاگ
        if (!actions.isEmpty()) {
            logger.warn("=== Required actions for " + entity.getUsername() + ": " + actions);
        }

        return actions.stream();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> attributes = this.getFederatedStorage()
                .getAttributes(this.realm, this.getId());
        if (attributes == null) {
            attributes = new MultivaluedHashMap();
        }
        attributes.add("employeeNumber", entity.getEmployeeNumber());
        List<String> firstName = (List)attributes.remove(FIRST_NAME_ATTRIBUTE);
        attributes.add("firstName", firstName != null && firstName.size() >= 1 ? (String)firstName.get(0) : null);
        List<String> lastName = (List)attributes.remove(LAST_NAME_ATTRIBUTE);
        attributes.add("lastName", lastName != null && lastName.size() >= 1 ? (String)lastName.get(0) : null);
        List<String> email = (List)attributes.remove(EMAIL_ATTRIBUTE);
        attributes.add("email", email != null && email.size() >= 1 ? (String)email.get(0) : null);
        attributes.add("username", this.getUsername());
        return attributes;
    }
    @Override
    public Stream<String> getAttributeStream(String name) {
        Map<String, List<String>> attributes = getAttributes();
        List<String> result = attributes.get(this.mapAttribute(name));
        return result == null ? Stream.empty() : result.stream();
    }

    // در UserAdapter
    /*@Override
    public Stream<RoleModel> getRoleMappingsStream() {
        // ۱. گرفتن roleهای federated
        Stream<RoleModel> federatedRoles = this.getFederatedRoleMappingsStream();

        // ۲. گرفتن roleهای internal (از entity)
        Stream<RoleModel> internalRoles = entity.getRoles() != null ?
                entity.getRoles().stream()
                        .map(r -> new CbglRole(r.getName(), "cbgl-role",
                                UUID.randomUUID().toString(), this.realm, false)) :
                Stream.empty();

        // ۳. گرفتن default roles realm
        Stream<RoleModel> defaultRoles = this.appendDefaultRolesToRoleMappings() ?
                this.realm.getDefaultRole().getCompositesStream() :
                Stream.empty();

        // ترکیب همه
        return Stream.of(federatedRoles, internalRoles, defaultRoles)
                .flatMap(s -> s)
                .distinct();
    }*/

/*    @Override
    public boolean hasRole(RoleModel role) {
        // ۱) نقش‌هایی که Keycloak از getRoleMappingsStream برایمان ساخته است
        boolean direct = RoleUtils.hasRole(this.getRoleMappingsStream(), role);

        // ۲) نقش‌هایی که از طریق Groupها به کاربر رسیده‌اند (اگر گروه دارید)
        boolean fromGroup = RoleUtils.hasRoleFromGroup(this.getGroupsStream(), role,
                true);
        logger.warnf("=== Checking role '%s' for %s: direct=%s, fromGroup=%s",
                role.getName(), getUsername(), direct, fromGroup);
        return direct || fromGroup;
    }*/

   /* @Override
    public void grantRole(RoleModel role) {
       // اگر کاربر قبلاً این نقش را دارد، کاری نکن
       if (this.hasRole(role))
           return;

       // فقط Realm Role می‌پذیریم (client role را رد می‌کنیم)
       if (role.isClientRole()) {
           logger.warnf("Ignoring client-role '%s' for user '%s' – read-only storage", role.getName(), getUsername());
           return;
       }

       // اگر نقش در Realm تعریف نشده باشد، خطا ندهیم، فقط لاگ
       if (realm.getRole(role.getName()) == null) {
           logger.warnf("Realm role '%s' not found – cannot grant to user '%s'", role.getName(), getUsername());
           return;
       }

       // ذخیره در federated storage (فقط در حافظه/کَش) – بدون تغییر دیتابیس ما
       this.getFederatedStorage().grantRole(this.realm, this.getId(), role);
       logger.debugf("Granted realm role '%s' to user '%s'", role.getName(), getUsername());
   }*/
   /* @Override
    public void deleteRoleMapping(RoleModel role) {
        // اگر نقش در Realm تعریف نشده باشد، خطا ندهیم، فقط لاگ
        if (realm.getRole(role.getName()) == null) {
            logger.warnf("Realm role '%s' not found – cannot grant to user '%s'", role.getName(), getUsername());
            return;
        }
        this.getFederatedStorage().deleteRoleMapping(this.realm, this.getId(), role);
    }*/

   /* @Override
    public void deleteRoleMapping(RoleModel role) {
        LOGGER.debugv("deleteRoleMapping called | User: {0} | Role: {1}", getUsername(), role.getName());

        // حذف از federated storage
        super.deleteRoleMapping(role);

        // حذف از internal entity هم
        if (entity.getRoles() != null) {
            entity.getRoles().removeIf(r -> r.getName().equals(role.getName()));
            LOGGER.debugv("Removed role {0} from internal entity", role.getName());
        }
    }*/
 /*   @Override
    public Stream<RoleModel> getFederatedRoleMappingsStream(){
        return this.getFederatedStorage().getRoleMappingsStream(this.realm, this.getId());
    }*/
}
