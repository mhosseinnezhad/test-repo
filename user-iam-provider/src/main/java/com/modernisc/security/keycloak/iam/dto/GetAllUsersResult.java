package com.modernisc.security.keycloak.iam.dto;

import java.util.List;
import java.util.StringJoiner;

public class GetAllUsersResult {

    private List<UserInfo> users;

    public List<UserInfo> getUsers() {
        return users;
    }

    public void setUsers(List<UserInfo> users) {
        this.users = users;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", "[", "]")
                .add("users=" + users)
                .toString();
    }
}
