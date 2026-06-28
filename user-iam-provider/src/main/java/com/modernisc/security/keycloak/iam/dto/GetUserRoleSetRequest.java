package com.modernisc.security.keycloak.iam.dto;

public class GetUserRoleSetRequest {

    private String userId;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
