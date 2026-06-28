package com.modernisc.security.keycloak.iam.dto;

import java.util.List;

public class GetSearchForUserResult {

    private List<UserInfo> users;

    public List<UserInfo> getUsers() {
        return users;
    }

    public void setUsers(List<UserInfo> users) {
        this.users = users;
    }
}
