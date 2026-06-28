package com.modernisc.security.keycloak.users.cbank.dto;

import java.util.StringJoiner;

public class GetUserByIdResult {

    private UserInfo user;

    public UserInfo getUser() {
        return user;
    }

    public void setUser(UserInfo user) {
        this.user = user;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", "[", "]")
                .add("user=" + user)
                .toString();
    }
}
