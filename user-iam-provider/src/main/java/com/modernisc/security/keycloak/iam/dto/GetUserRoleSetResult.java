package com.modernisc.security.keycloak.iam.dto;

import java.util.List;

public class GetUserRoleSetResult {

    private List<RoleInfo> roles;

    public List<RoleInfo> getRoles() {
        return roles;
    }

    public void setRoles(List<RoleInfo> roles) {
        this.roles = roles;
    }
}
