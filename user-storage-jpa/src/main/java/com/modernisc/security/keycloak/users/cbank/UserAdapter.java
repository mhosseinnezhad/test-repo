package com.modernisc.security.keycloak.users.cbank;

import com.modernisc.security.keycloak.users.cbank.dto.GetUserRoleSetResult;
import com.modernisc.security.keycloak.users.cbank.dto.RoleInfo;
import com.modernisc.security.keycloak.users.cbank.dto.UserInfo;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

import java.io.IOException;
import java.security.*;
import java.text.MessageFormat;
import java.util.*;

import static com.modernisc.security.keycloak.users.cbank.util.ExceptionUtil.getChainCauseMessage;

public class UserAdapter extends AbstractUserAdapterFederatedStorage {
    private static final Logger LOGGER = Logger.getLogger(UserAdapter.class);
    private static final Logger SECURITY_LOGGER = Logger.getLogger("com.modernisc.security.log");
    private final NakisaService nakisaService;
    protected UserInfo entity;
    protected String keycloakId;


    public UserAdapter(KeycloakSession session, RealmModel realm,
                       ComponentModel model, UserInfo entity, NakisaService nakisaService) {
        super(session, realm, model);
        this.entity = entity;
        keycloakId = StorageId.keycloakId(model, String.valueOf(entity.getId()));
        this.nakisaService = nakisaService;
    }

    public String getPassword() {
        return "";
    }

    public void setPassword(String password) {

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
    public String getId() {
        return keycloakId;
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        if (name.equals("phone")) {
            //entity.setPhone(value);
        } else {
            super.setSingleAttribute(name, value);
        }
    }

    @Override
    public void removeAttribute(String name) {
        if (name.equals("phone")) {
            //entity.setPhone(null);
        } else {
            super.removeAttribute(name);
        }
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        if (name.equals("phone")) {
             //entity.setMobilephone(values.get(0));
        } else {
            super.setAttribute(name, values);
        }
    }

    @Override
    public String getFirstAttribute(String name) {
        if (name.equals("phone")) {
            // return entity.getPhone();
            return super.getFirstAttribute(name);
        } else {
            return super.getFirstAttribute(name);
        }
    }

    @Override
    protected Set<RoleModel> getFederatedRoleMappings() {
        Set<RoleModel> roles = new HashSet<>();

        return super.getFederatedRoleMappings();
    }

    @Override
    protected Set<RoleModel> getRoleMappingsInternal() {
        Set<RoleModel> res = new HashSet<>();
        List<RoleInfo> userRoles = getUserRoleSet(this.entity.getId());

        for(RoleInfo s : userRoles ){
            res.add(new AbisRole(s.getCode(), "abis-role", UUID.randomUUID().toString(), this.realm));
        }

        return res;
    }

    public List<RoleInfo> getUserRoleSet(long userId) {
        GetUserRoleSetResult result;
        try {
            result = nakisaService.getUserRoleSet(userId);
        } catch (IOException | GeneralSecurityException exp) {
            LOGGER.error(MessageFormat.format("Error in user login in nakisa. {0}", getChainCauseMessage(exp)));
            SECURITY_LOGGER.error(MessageFormat.format("Error in user login in nakisa. {0}", getChainCauseMessage(exp)));
            return null;
        }

        return result.getRoles();
    }

}
