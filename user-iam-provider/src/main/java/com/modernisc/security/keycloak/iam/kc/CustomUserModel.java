package com.modernisc.security.keycloak.iam.kc;

import com.modernisc.security.keycloak.iam.dto.GetUserRoleSetResult;
import com.modernisc.security.keycloak.iam.dto.RoleInfo;
import com.modernisc.security.keycloak.iam.service.CustomService;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.modernisc.security.keycloak.iam.util.ExceptionUtil.getChainCauseMessage;

public class CustomUserModel
        extends AbstractUserAdapterFederatedStorage {

    private static final Logger logger = Logger.getLogger(CustomUserModel.class);
    private static final Logger SECURITY_LOGGER = Logger.getLogger("com.modernisc.security.log");
    protected CustomUser entity;
    protected String keycloakId;
    private final CustomService customService;
    private RealmModel realm;
    private KeycloakSession session;
    private ComponentModel model;

    public CustomUserModel(KeycloakSession session, RealmModel realm, ComponentModel model
            , CustomUser userDto, CustomService customService) {
        super(session, realm, model);
        if (model == null) {
            logger.error("=== FATAL: ComponentModel is NULL ===");
        }
        if (userDto == null) {
            logger.error("=== FATAL: User entity is NULL ===");
        }
        this.realm = realm;
        this.session = session;
        this.entity = userDto;
        this.model = model;
        setCreatedTimestamp(new Date().getTime());
        keycloakId = StorageId.keycloakId(model, String.valueOf(entity.getId()));
        this.customService = customService;
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
        entity.setUsername(username);
    }

    @Override
    public Long getCreatedTimestamp() {
        long millis = entity.getCreatedTimeStamp()
                .toInstant()
                .toEpochMilli();

        return millis;
    }

    @Override
    public void setCreatedTimestamp(Long aLong) {
        entity.setCreatedTimeStamp(  new Date(aLong) );
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

    @Override
    public void setEnabled(boolean b) {
        entity.setEnabled(Boolean.toString(b));
    }

    @Override
    public void setSingleAttribute(String s, String s1) {

    }

    @Override
    public void addRequiredAction(String s) {

    }

    @Override
    public void removeRequiredAction(String s) {

    }


    @Override
    public void setFirstName(String s) {

        entity.setFirstName(s);
    }

    @Override
    public void setLastName(String s) {
        entity.setLastName(s);
    }


    @Override
    public void setEmail(String s) {
        entity.setEmail(entity.getEmail());
    }



    @Override
    public void setEmailVerified(boolean b) {
        entity.setEmailVerified(Boolean.toString(b));
    }


    @Override
    protected Set<RoleModel> getRoleMappingsInternal() {
        Set<RoleModel> roleModels = new HashSet<>();
        List<RoleInfo> userRoles = getUserRoleSet(this.entity.getId());
        if (userRoles != null) {

            for (RoleInfo role : userRoles) {
                //RoleModel realmRole = realm.getRole(role.getCode());
                //if (realmRole != null) {
                    roleModels.add(new CustomRole(role.getCode(),
                            "iam-role", UUID.randomUUID().toString(), this.realm));
                //}
            }
        }
        return roleModels;
    }
    public boolean isTemporary() {
        return false;//userEntity.isTemporary();
    }

    public void setTemporary(boolean temporary) {
        //userEntity.setTemporary(temporary);
    }
    @Override
    public String getServiceAccountClientLink() {
        if(super.getServiceAccountClientLink()!=null)
            return super.getServiceAccountClientLink();
        return serviceAccountClientLink;
    }

    String serviceAccountClientLink;
    @Override
    public void setServiceAccountClientLink(String s) {
        serviceAccountClientLink = s;
    }
    public List<RoleInfo> getUserRoleSet(long userId) {
        GetUserRoleSetResult result;
        try {
            result = customService.getUserRoleSet(userId);
        } catch (GeneralSecurityException | IOException exp) {
            logger.error(MessageFormat.format("Error in user login in custom. {0}", getChainCauseMessage(exp)));
            SECURITY_LOGGER.error(MessageFormat.format("Error in user login in custom. {0}", getChainCauseMessage(exp)));
            return null;
        }

        if(result==null)
            return Collections.EMPTY_LIST;
        return result.getRoles();
    }

    public String getUserByEmail(UserModel user) {
        return user.getEmail();
    }


    @Override
    public boolean isEmailVerified() {

        return entity.getEmailVerified() != null &&
                Boolean.parseBoolean(entity.getEmailVerified());
    }
    @Override
    public String getFirstAttribute(String name) {
        Map<String, List<String>> attrs = getAttributes();
        if(attrs != null) {
            return attrs.get(name) != null ? attrs.get(name).getFirst() : null;
        }
        return null;
    }

    @Override
    public Stream<String> getRequiredActionsStream() {
        logger.warn("=== Skipping required actions for: " + entity.getUsername());
        List<String> actions = new ArrayList<>();

        // اگر کاربر موقت است، حتماً باید پسورد عوض کند
        if (entity.getTemporary()) {
            actions.add(UserModel.RequiredAction.UPDATE_PASSWORD.name());
        }

        // اگر پسورد منقضی شده
        if (entity.getPasswordExpirationDate() != null &&
                !entity.getPasswordExpirationDate().equals(LocalDateTime.MAX) &&
                entity.getPasswordExpirationDate().toInstant()
                        .isBefore(Instant.now())) {
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
        if (this.getFederatedStorage() != null) {
            MultivaluedHashMap<String, String> attributes = this.getFederatedStorage()
                    .getAttributes(this.realm, this.getId());
            if (attributes == null) {
                attributes = new MultivaluedHashMap();
            }
            attributes.add("uuid", entity.getUuid());
            List<String> firstName = (List) attributes.remove(FIRST_NAME_ATTRIBUTE);
            attributes.add("firstName", firstName != null && firstName.size() >= 1 ? (String) firstName.get(0) : null);
            List<String> lastName = (List) attributes.remove(LAST_NAME_ATTRIBUTE);
            attributes.add("lastName", lastName != null && lastName.size() >= 1 ? (String) lastName.get(0) : null);
            List<String> email = (List) attributes.remove(EMAIL_ATTRIBUTE);
            attributes.add("email", email != null && email.size() >= 1 ? (String) email.get(0) : null);
            attributes.add("username", this.getUsername());
            return attributes;
        }
        return Collections.EMPTY_MAP;
    }
    @Override
    public Stream<String> getAttributeStream(String name) {
        Map<String, List<String>> attributes = getAttributes();
        List<String> result = attributes.get(this.mapAttribute(name));
        return result == null ? Stream.empty() : result.stream();
    }
    @Override
    public Stream<RoleModel> getRoleMappingsStream() {
        Stream<RoleModel> roleMappings = this.getFederatedRoleMappingsStream();
        if (this.appendDefaultRolesToRoleMappings()) {
            roleMappings = Stream.concat(roleMappings, this.realm.getRolesStream());
        }

        return Stream.concat(roleMappings, this.getRoleMappingsInternal().stream());
    }
    @Override
    public boolean hasRole(RoleModel role) {
        // ۱) نقش‌هایی که Keycloak از getRoleMappingsStream برایمان ساخته است
        boolean direct = RoleUtils.hasRole(this.getRoleMappingsStream(), role);

        // ۲) نقش‌هایی که از طریق Groupها به کاربر رسیده‌اند (اگر گروه دارید)
        boolean fromGroup = RoleUtils.hasRoleFromGroup(this.getGroupsStream(), role,
                true);
        logger.warnf("=== Checking role '%s' for %s: direct=%s, fromGroup=%s",
                role.getName(), getUsername(), direct, fromGroup);
        return direct || fromGroup;
    }

    @Override
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
    }

    @Override
    public Stream<RoleModel> getClientRoleMappingsStream(ClientModel client) {
        return getUserRoleSet(entity.getId()).stream()
                .map(roleName -> client.getRole(roleName.getCode()))
                .filter(Objects::nonNull)
                .filter((r) -> RoleUtils.isClientRole(r, client));
    }
}

