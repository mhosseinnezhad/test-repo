package com.modernisc.security.keycloak;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.UserCredentialStore;
import org.keycloak.models.*;
import org.keycloak.models.cache.UserCache;
import org.keycloak.storage.federated.UserFederatedStorageProvider;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;


public class CustomUserFederatedStorageProvider implements UserFederatedStorageProvider, UserCredentialStore {

    private static final Logger LOGGER = Logger.getLogger(CustomUserFederatedStorageProvider.class);
    private static final Logger SECURITY_LOGGER = Logger.getLogger("com.modernisc.security.log");

    protected KeycloakSession session;

    public CustomUserFederatedStorageProvider(KeycloakSession session) {
        this.session = session;

    }


    @Override
    public Stream<String> getStoredUsersStream(RealmModel realmModel, Integer integer,
                                               Integer integer1) {
        return Stream.empty();
    }

    @Override
    public int getStoredUsersCount(RealmModel realmModel) {
        return 0;
    }

    @Override
    public void preRemove(RealmModel realmModel) {

    }

    @Override
    public void preRemove(RealmModel realmModel, GroupModel groupModel) {

    }

    @Override
    public void preRemove(RealmModel realmModel, RoleModel roleModel) {

    }

    @Override
    public void preRemove(RealmModel realmModel, ClientModel clientModel) {

    }

    @Override
    public void preRemove(ProtocolMapperModel protocolMapperModel) {

    }

    @Override
    public void preRemove(ClientScopeModel clientScopeModel) {

    }

    @Override
    public void preRemove(RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void preRemove(RealmModel realmModel, ComponentModel componentModel) {

    }

    @Override
    public void close() {

    }

    @Override
    public void setSingleAttribute(RealmModel realmModel, String s, String s1, String s2) {

    }

    @Override
    public void setAttribute(RealmModel realmModel, String s, String s1, List<String> list) {

    }

    @Override
    public void removeAttribute(RealmModel realmModel, String s, String s1) {

    }
    private EntityManager getEntityManager() {
        return session.getProvider(JpaConnectionProvider.class).getEntityManager();
    }
    @Override
    public MultivaluedHashMap<String, String> getAttributes(RealmModel realmModel,
                                                            String name) {

        MultivaluedHashMap<String, String> result = new MultivaluedHashMap<>();


        return result;
    }

    @Override
    public Stream<String> getUsersByUserAttributeStream(RealmModel realmModel,
                                                        String s, String s1) {
        return Stream.empty();
    }

    @Override
    public String getUserByFederatedIdentity(FederatedIdentityModel federatedIdentityModel, RealmModel realmModel) {
        return "";
    }

    @Override
    public void addFederatedIdentity(RealmModel realmModel, String s,
                                     FederatedIdentityModel federatedIdentityModel) {

    }

    @Override
    public boolean removeFederatedIdentity(RealmModel realmModel,
                                           String s, String s1) {
        return false;
    }

    @Override
    public void preRemove(RealmModel realmModel, IdentityProviderModel identityProviderModel) {

    }

    @Override
    public void updateFederatedIdentity(RealmModel realmModel, String s,
                                        FederatedIdentityModel federatedIdentityModel) {

    }

    @Override
    public Stream<FederatedIdentityModel> getFederatedIdentitiesStream(String s,
                                                                       RealmModel realmModel) {
        return Stream.empty();
    }

    @Override
    public FederatedIdentityModel getFederatedIdentity(String s, String s1,
                                                       RealmModel realmModel) {
        return null;
    }

    @Override
    public void addConsent(RealmModel realmModel, String s, UserConsentModel userConsentModel) {

    }

    @Override
    public UserConsentModel getConsentByClient(RealmModel realmModel,
                                               String s, String s1) {
        return null;
    }

    @Override
    public Stream<UserConsentModel> getConsentsStream(RealmModel realmModel,
                                                      String s) {
        return Stream.empty();
    }

    @Override
    public void updateConsent(RealmModel realmModel, String s,
                              UserConsentModel userConsentModel) {

    }

    @Override
    public boolean revokeConsentForClient(RealmModel realmModel,
                                          String s, String s1) {
        return false;
    }

    @Override
    public void updateCredential(RealmModel realmModel, String s,
                                 CredentialModel credentialModel) {

    }

    @Override
    public CredentialModel createCredential(RealmModel realmModel,
                                            String s, CredentialModel credentialModel) {
        return null;
    }

    @Override
    public boolean removeStoredCredential(RealmModel realmModel,
                                          String s, String s1) {
        return false;
    }

    @Override
    public CredentialModel getStoredCredentialById(RealmModel realmModel,
                                                   String s, String s1) {
        return null;
    }

    @Override
    public Stream<CredentialModel> getStoredCredentialsStream(RealmModel realmModel, String s) {
        return Stream.empty();
    }

    @Override
    public Stream<CredentialModel> getStoredCredentialsByTypeStream(RealmModel realmModel,
                                                                    String s, String s1) {
        return Stream.empty();
    }

    @Override
    public CredentialModel getStoredCredentialByNameAndType(RealmModel realmModel,
                                                            String s, String s1, String s2) {
        return null;
    }

    @Override
    public Stream<GroupModel> getGroupsStream(RealmModel realmModel,
                                              String s) {
        return Stream.empty();
    }

    @Override
    public void joinGroup(RealmModel realmModel, String s, GroupModel groupModel) {

    }

    @Override
    public void leaveGroup(RealmModel realmModel, String s,
                           GroupModel groupModel) {

    }

    @Override
    public Stream<String> getMembershipStream(RealmModel realmModel,
                                              GroupModel groupModel, Integer integer, Integer integer1) {
        return Stream.empty();
    }

    @Override
    public void setNotBeforeForUser(RealmModel realmModel,
                                    String s, int i) {

    }

    @Override
    public int getNotBeforeOfUser(RealmModel realmModel,
                                  String s) {
        return 0;
    }

    @Override
    public Stream<String> getRequiredActionsStream(RealmModel realmModel,
                                                   String s) {
        return Stream.empty();
    }

    @Override
    public void addRequiredAction(RealmModel realmModel, String s, String s1) {

    }

    @Override
    public void removeRequiredAction(RealmModel realmModel, String s, String s1) {

    }

    @Override
    public void grantRole(RealmModel realm, String userId, RoleModel role) {
        if (realm == null || userId == null || role == null) {
            LOGGER.warn("Invalid parameters for grantRole");
            return;
        }

        // Extract internal ID از federated ID
        String internalUserId = extractInternalId(userId);
        String roleId = role.getId();
        String roleName = role.getName();

        LOGGER.debugv("Granting role | User: {0} (internal: {1}) | Role: {2} | Realm: {3}",
                userId, internalUserId, roleName, realm.getName());

        EntityManager em = null;
        try {
            em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

            if (!em.getTransaction().isActive()) {
                em.getTransaction().begin();
            }

            // بررسی آیا قبلاً وجود دارد
            String checkSql = "SELECT COUNT(*) FROM FED_USER_ROLE_MAPPING " +
                    "WHERE USER_ID = :userId AND ROLE_ID = :roleId";

            Number count = (Number) em.createNativeQuery(checkSql)
                    .setParameter("userId", internalUserId)
                    .setParameter("roleId", roleId)
                    .getSingleResult();

            if (count.intValue() > 0) {
                LOGGER.debugv("Role already assigned | User: {0} | Role: {1}", userId, roleName);
                em.getTransaction().rollback();
                return;
            }

            // Insert جدید
            String insertSql = "INSERT INTO FED_USER_ROLE_MAPPING (USER_ID, ROLE_ID) " +
                    "VALUES (:userId, :roleId)";

            em.createNativeQuery(insertSql)
                    .setParameter("userId", internalUserId)
                    .setParameter("roleId", roleId)
                    .executeUpdate();

            em.getTransaction().commit();

            // Evict cache
            evictUserCache(realm, userId);

            SECURITY_LOGGER.infov("ROLE_GRANTED | User: {0} | Role: {1} | Realm: {2}",
                    userId, roleName, realm.getName());

            LOGGER.infov("Role granted successfully | User: {0} | Role: {1}", userId, roleName);

        } catch (Exception e) {
            if (em != null && em.getTransaction().isActive()) {
                em.getTransaction().rollback();
            }
            LOGGER.errorv(e, "Failed to grant role | User: {0} | Role: {1}", userId, roleName);
            throw new RuntimeException("Failed to grant role", e);
        }
    }
    @Override
    public Stream<RoleModel> getRoleMappingsStream(RealmModel realm, String userId) {
        if (realm == null || userId == null) {
            return Stream.empty();
        }

        // Extract internal ID
        String internalId = extractInternalId(userId);

        LOGGER.debugv("Getting roles for user | FederatedId: {0} | InternalId: {1}", userId, internalId);

        try {
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

            // امتحان با internal ID
            Stream<RoleModel> roles = getRolesByUserId(em, realm, internalId);

            // اگر خالی بود، امتحان با federated ID
            if (roles.count() == 0) {
                roles = getRolesByUserId(em, realm, userId);
            }

            return roles;

        } catch (Exception e) {
            LOGGER.errorv(e, "Failed to get roles for user: {0}", userId);
            return Stream.empty();
        }
    }

    private Stream<RoleModel> getRolesByUserId(EntityManager em, RealmModel realm, String userId) {
        String sql = "SELECT r.ID, r.NAME, r.DESCRIPTION " +
                "FROM FED_USER_ROLE_MAPPING urm " +
                "JOIN KEYCLOAK_ROLE r ON urm.ROLE_ID = r.ID " +
                "WHERE urm.USER_ID = :userId";

        @SuppressWarnings("unchecked")
        List<Object[]> results = em.createNativeQuery(sql)
                .setParameter("userId", userId)
                .getResultList();

        return results.stream()
                .map(row -> {
                    String roleId = (String) row[0];
                    return realm.getRoleById(roleId);
                })
                .filter(Objects::nonNull);
    }
    /*public Stream<RoleModel> getDirectRoles(RealmModel realm, String userId) {
        if (realm == null || userId == null) {
            return Stream.empty();
        }

        // گرفتن UserModel و استفاده از متد داخلی آن
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            LOGGER.warnv("User not found: {0}", userId);
            return Stream.empty();
        }

        // UserModel خودش getRoleMappingsStream دارد
        return user.getRoleMappingsStream();
    }*/

   /* @Override
    public void deleteRoleMapping(RealmModel realm, String userId, RoleModel role) {
        if (realm == null || userId == null || role == null) {
            LOGGER.warn("Invalid parameters for deleteRoleMapping");
            return;
        }

        String realmId = realm.getId();
        String roleId = role.getId();
        String roleName = role.getName();
        // Extract internal ID from federated ID
        String internalUserId = extractInternalId(userId);
        LOGGER.debugv("Attempting to unassign role | User: {0} | Role: {1} | Realm: {2}",
                userId, roleName, realmId);

        try {
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            // بررسی آیا transaction فعال است
            if (!em.getTransaction().isActive()) {
                em.getTransaction().begin();
            }
            // استفاده از JPQL معمولی به جای NamedQuery
            String jpql = "DELETE FROM UserRoleMappingEntity m WHERE m.user.id = :userId AND m.roleId = :roleId";

            int deleted = em.createQuery(jpql)
                    .setParameter("userId", userId)
                    .setParameter("roleId", roleId)
                    .executeUpdate();

            if (deleted > 0) {
                // Invalidate cache
                UserCache userCache = session.getProvider(UserCache.class);
                userCache.evict(realm, userCache.getUserById(realm,userId));

                SECURITY_LOGGER.infov("SECURITY_EVENT: ROLE_UNASSIGNED | UserID: {0} | Role: {1} | Realm: {2}",
                        userId, roleName, realmId);

                LOGGER.infov("Role successfully unassigned | User: {0} | Role: {1}", userId, roleName);
            } else {
                LOGGER.warnv("No role mapping found to delete | User: {0} | Role: {1}", userId, roleName);
            }

        } catch (Exception e) {
            LOGGER.errorv(e, "Failed to delete role mapping for user {0} and role {1}", userId, roleName);
            throw new RuntimeException("Failed to unassign role", e);
        }
    }*/
    @Override
    public void deleteRoleMapping(RealmModel realm, String userId, RoleModel role) {
        if (realm == null || userId == null || role == null) {
            LOGGER.warn("Invalid parameters for deleteRoleMapping");
            return;
        }

        String roleId = role.getId();
        String roleName = role.getName();

        // Extract internal ID from federated ID
        String internalUserId = extractInternalId(userId);

        LOGGER.debugv("Attempting to unassign role | FederatedUserId: {0} | InternalUserId: {1} | Role: {2} | Realm: {3}",
                userId, internalUserId, roleName, realm.getName());

        EntityManager em = null;
        try {
            em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

            // بررسی آیا transaction فعال است
            if (!em.getTransaction().isActive()) {
                em.getTransaction().begin();
            }

            // حذف از USER_ROLE_MAPPING - با internal ID
            String deleteSql = "DELETE FROM FED_USER_ROLE_MAPPING " +
                    "WHERE USER_ID = :userId AND ROLE_ID = :roleId";

            int deleted = em.createNativeQuery(deleteSql)
                    .setParameter("userId", userId)  // ← استفاده از internal ID
                    .setParameter("roleId", roleId)
                    .executeUpdate();

            LOGGER.debugv("Deleted {0} rows from USER_ROLE_MAPPING", deleted);

            // حذف از USER_ROLE_MAPPING اگر با federated ID ذخیره شده
            if (deleted == 0) {
                String deleteSql2 = "DELETE FROM FED_USER_ROLE_MAPPING " +
                        "WHERE USER_ID = :userId AND ROLE_ID = :roleId";

                deleted = em.createNativeQuery(deleteSql2)
                        .setParameter("userId", internalUserId)  // ← امتحان با federated ID
                        .setParameter("roleId", roleId)
                        .executeUpdate();

                LOGGER.debugv("Deleted {0} rows with federated ID", deleted);
            }

            // Commit
            em.getTransaction().commit();

            if (deleted > 0) {
                // Evict cache - با federated ID
                evictUserCache(realm, userId);

                SECURITY_LOGGER.infov("ROLE_UNASSIGNED | User: {0} | Role: {1} | Realm: {2}",
                        userId, roleName, realm.getName());

                LOGGER.infov("Role unassigned successfully | User: {0} | Role: {1}", userId, roleName);
            } else {
                LOGGER.warnv("No role mapping found | User: {0} (internal: {1}) | Role: {2}",
                        userId, internalUserId, roleName);
            }

        } catch (Exception e) {
            if (em != null && em.getTransaction().isActive()) {
                em.getTransaction().rollback();
            }
            LOGGER.errorv(e, "Failed to unassign role | User: {0} | Role: {1}", userId, roleName);
            throw new RuntimeException("Failed to unassign role", e);
        }
    }

    /**
     * Extract internal ID from federated ID format: f:uuid:internalId
     */
    private String extractInternalId(String federatedId) {
        if (federatedId == null) return null;

        int lastColon = federatedId.lastIndexOf(':');
        if (lastColon > 0 && lastColon < federatedId.length() - 1) {
            return federatedId.substring(lastColon + 1);
        }
        return federatedId;
    }

    /**
     * Evict user from cache
     */
    private void evictUserCache(RealmModel realm, String userId) {
        try {
            UserCache userCache = session.getProvider(UserCache.class);
            if (userCache != null) {
                // با federated ID
                userCache.evict(realm, userCache.getUserById(realm,userId));

                // با internal ID هم امتحان کن
                String internalId = extractInternalId(userId);
                if (!internalId.equals(userId)) {
                    try {
                        userCache.evict(realm, userCache.getUserById(realm,internalId));
                    } catch (Exception e) {
                        // ignore
                        e.printStackTrace();
                    }
                }

                LOGGER.debugv("Cache evicted for user: {0}", userId);
            }
        } catch (Exception e) {
            LOGGER.warnv(e, "Failed to evict cache for user: {0}", userId);
        }
    }
    @Override
    public Stream<String> getRoleMembersStream(RealmModel realmModel,
                                               RoleModel roleModel, Integer integer,
                                               Integer integer1) {
        return Stream.empty();
    }

    @Override
    public void updateCredential(RealmModel realmModel, UserModel userModel,
                                 CredentialModel credentialModel) {

    }

    @Override
    public CredentialModel createCredential(RealmModel realmModel,
                                            UserModel userModel, CredentialModel credentialModel) {
        return null;
    }

    @Override
    public boolean removeStoredCredential(RealmModel realmModel,
                                          UserModel userModel, String s) {
        return false;
    }

    @Override
    public CredentialModel getStoredCredentialById(RealmModel realmModel,
                                                   UserModel userModel, String s) {
        return null;
    }

    @Override
    public Stream<CredentialModel> getStoredCredentialsStream(RealmModel realmModel,
                                                              UserModel userModel) {
        return Stream.empty();
    }

    @Override
    public Stream<CredentialModel> getStoredCredentialsByTypeStream(RealmModel realmModel,
                                                                    UserModel userModel, String s) {
        return Stream.empty();
    }

    @Override
    public CredentialModel getStoredCredentialByNameAndType(RealmModel realmModel,
                                                            UserModel userModel, String s, String s1) {
        return null;
    }

    @Override
    public boolean moveCredentialTo(RealmModel realmModel, UserModel userModel,
                                    String s, String s1) {
        return false;
    }
}
