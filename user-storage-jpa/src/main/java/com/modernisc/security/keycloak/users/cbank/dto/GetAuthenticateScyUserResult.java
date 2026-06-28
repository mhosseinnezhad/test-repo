package com.modernisc.security.keycloak.users.cbank.dto;

import java.util.StringJoiner;

public class GetAuthenticateScyUserResult {

    private String authenticated;

    public String getAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(String authenticated) {
        this.authenticated = authenticated;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", "[", "]")
                .add("authenticated=" + authenticated)
                .toString();
    }
}
